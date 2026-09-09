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

## What the riegel sweep left open — measured by a lens, and three of four were wrong

**Why this section exists.** The preamble of this file promises that *every finding that stays open
is named here*. On 2026-09-07 a lens measured that promise against the file and found it broken:
three findings of the riegel sweep lived only as prose in `audit_artifacts/600/README.md`, without a
register key, without a severity, without a funnel verdict. This section closes that gap under rule 2
of the standard rather than as an exception — the round that found them produced a **new freeze**,
which is exactly the path the section three above prescribes.

**And then a second lens measured the three entries themselves.** It found that they were not
equally harmless: one was a real P1 with an executed amplification probe, one had a **factually
wrong** deferral reason and a cheap fix, and one was no finding at all. A residual-risk line that
files three unequal things as equal is more honest than silence and still wrong. What follows is the
corrected state; the two P0 the round found are not here, because a closed finding is not a residual
risk.

### S1 · Budget call sites — five are unreachable, the sixth was a real P1 and is now CLOSED

The sweep filed six unbound budget call sites as one group. A lens mutated **all six at once**
(`pass` instead of the check, digest compared before and after, mutation read back) and ran the
1414-test slice on the clean and the mutated tree: **both runs `1412 passed, 2 skipped, 0 failed` —
identical.** Then it separated them.

**Five are PROVABLY DEAD, not merely untested.** `dsse.load_payload()` — one line earlier in each of
the six paths — already enforces `string_len` (1 000 000) on the base64 payload, and 1 000 000 base64
characters decode to at most ~750 KB, so the local `input_bytes` comparison (8 388 608) is never
reached. Measured with a 2 MB payload probe, corroborated by the project's own cost-curve
measurement, and both constants are pinned in both directions — so the safe relation cannot lapse
silently.

**The sixth was real.** `verify_trust_pack` never calls `dsse.verify_envelope` — it has its own
threshold loop — so it does not benefit from the cap set there. Without its local cap the only
backstop is `json_nodes` (200 000), roughly 390× looser, because a signature entry costs about three
nodes. Measured with a genuine signed pack inflated with structurally valid, cryptographically wrong
entries: with the cap every list over 512 is refused; without it, 66 600 entries are accepted as a
VALID pack after ~0.17 s of real Ed25519 work, roughly 130× the documented worst case. **No test in
the repository called `verify_trust_pack` with an overlong signature list** — the similarly named
`test_resource_budget_bites_on_wide_signatures` exercises `dsse.verify_envelope`, a different path.
A neighbour that looks like the binding and is not one.

**CLOSED** in this round by `tests/test_trust_pack_signaturdeckel_beisst.py`, which binds the
**effect** rather than the message: it counts how often the crypto check is entered at all. With the
cap, zero; without it, one call per entry. The verdict alone cannot tell the two states apart —
`ok` is `False` either way, because the entries are invalid — which is exactly why the case counts
work instead of reading text. Catch-proof announced before the run and measured after: **1 of 3**.

### S2 · The package-guard skip assertion — CLOSED, and the deferral reason was wrong

The assertion that was supposed to hold the SKIP count read the COLLECTED count instead. The sweep
deferred it with the reason *"binding it needs a real sdist as its measurement surface"*. **A lens
falsified that reason.** A minimal throwaway tree suffices — `conftest.py`, the two cited test
modules, and the two scripts they load AT IMPORT time; no sdist build. Measured: exactly `34 skipped`
and `9 skipped`, zero collection errors, matching the header. Control: the same tree WITHOUT
`scripts/` reproduces the earlier failure exactly (two collection errors). The first attempt failed
on **incompleteness, not on structure** — and one incomplete measurement was turned into an
impossibility.

**CLOSED** in this round by
`test_die_zahl_im_kopf_ist_eine_SKIP_zahl_und_wird_als_SKIP_zahl_gemessen`, which runs a real
`pytest -rs` in that tree. Catch-proof announced and measured: with `modul_ist_repo_kontext` forced
to `return False`, **2 of 7** fall — the new case and the derivation control — while the
collected-count case stays GREEN. That difference is the whole reason the case exists.

### S3 · `pre_tag_audit_gate` first-candidate acceptance — NO FINDING, measured in both directions

The sweep recorded this as "probably intended, measured in neither direction". It is now measured.
The only genuine first-candidate pattern (`recs[0]` in `audit_artifact_for`) is a vestigial legacy
function called only from tests; the live gate path (`evaluate()`) does not use it and evaluates ALL
candidates independently as a union. Measured with two probe repositories, good and bad candidate in
both alphabetical orders: correct classification regardless of file order. An attacker cannot
displace a genuine candidate or smuggle a false one through by naming files. **Recorded as closed
with its measurement, not carried as an open risk.**

### S4 · A shipped prose document drifted from the corpus it describes — CLOSED, and the deferral was again too cautious

`CROSS_IMPLEMENTATION_REPORT.md` states the corpus grew "to 57 cases … 56/56". Measured on this
head: the corpus holds **107** cases and `crosscheck.py` reproduces **57**, the rest declared
Python-only. The document opens by saying of itself that it is prose and that prose drifts, and it
names `scripts/rust_parity_gate.py` as the living source — so the drift is already structurally
caught. It is listed because the promise at the top of THIS file is about every open finding, not
about every important one. **Funnel: it can mislead a reader** who takes the prose for the
measurement. Register key: `PROSA-BERICHT-DRIFTET-VON-SEINEM-KORPUS-01`.

**CLOSED on 2026-09-08, and the closing is itself a data point.** This entry was filed as "already
structurally caught, the document says of itself that prose drifts" — which is true and was used as a
reason not to touch it. Ledger class 234 (*a deferral needs the same evidence as a finding*) carried
a falsifiable prediction: that at least one of the remaining open items would close in under an hour,
and it named the one I least expected. This was not that one — it was the one I had called
self-correcting. It took **one command and one sentence**: `crosscheck.py` prints its own verdict,
and it reads **57 of 107**, 42 of them relation vectors compared differentially.

The sentence that stood there claimed "All corpus cases are reproduced independently" and then
"56/56 as of v3.7.0". Each half was true of a smaller, older corpus; together they read as full
coverage of the current one. That is the same shape as the release record's own recurring defect — a
verdict over an excerpt, phrased as a verdict over the whole — in a document that ships. It now names
the command, the date, and the remainder that is declared Python-only.

**Score of my own deferral estimates in this cycle: 0 of 4.** Three were closed by someone else
pointing at them, this one by finally running the command I had argued did not need running.

### What this correction is itself an instance of

Three of four entries written in one round were wrong within the same round — not in their facts but
in their **severity and their reasons**. The shared shape: a finding was filed with the confidence of
a measurement while resting on a single incomplete attempt. `S1` grouped six things that measure
differently, `S2` promoted one failed setup to a law of nature, `S3` called an unmeasured thing
"probably intended". The lens that took each of them apart did nothing this round could not have
done — it just did not stop at the first answer. Register key:
`DREI-VON-VIER-RESTRISIKO-EINTRAEGEN-FALSCH-EINGESTUFT-IN-DERSELBEN-RUNDE-01`.

### S5 · The two new riegel are bound one at a time, never together — open, named by the cross-family lens

Fix 1 bounds the crypto work of `verify_trust_pack`; fix 2 binds the skip count of the package
guard. **No case asserts that both hold at the same time.** The lens that named it put the
consequence plainly: cap gone AND skip count wrong means an oversized pack is accepted after real
Ed25519 work while the guard reports a figure that no longer describes anything — and not one case
catches the combination.

**Why it stays open rather than being closed here:** the two riegel live on unrelated surfaces
(a verifier's resource bound and a test-suite bookkeeping figure), so a combined case would be a
product of two independent axes rather than a property either one has. Building it well is a
combinatorial question, and building it badly would be a case that passes for reasons neither axis
supplies — the exact failure this cycle spent its day removing. **Funnel: it does not add a path a
user can reach**; each riegel is bound individually and measured red without its fix. Register key:
`ZWEI-RIEGEL-EINZELN-GEBUNDEN-IHRE-KOMBINATION-NICHT-01`.

**A second point from the same lens — and it turned out smaller than a follow-up, so it is CLOSED
here.** In a real sdist a module could skip for a DIFFERENT reason (a missing optional dependency, a
platform check); the count would then be right for the wrong reason and the assertion would pass.
The case now binds the CAUSE as well: `conftest.py` writes the identifier `PKG-2026-0718-01` into the
skip reason, and the case reads it out of the `-rs` output alongside the count.

Catch-proof, announced before the run and measured after: replace ONLY the reason text, leave the
count untouched — **1 of 7** falls, and it is the new case, failing on the reason line rather than on
the number. Sharper than intended: the identifier still appears in the module's docstring and only
the skip reason lost it, and the case fails anyway. It reads the REASON, not the file. Register key:
`DIE-SKIP-ZAHL-IST-GEBUNDEN-IHR-GRUND-NICHT-01`, closed.

### Where the round's own method failed, and what actually caught it

The owner reversed the order after the third relapse: catch-proof first, red against the defective
state, number announced, only then the change. Both remaining fixes were built that way, and both
announcements were hit exactly. **It was not enough.** The counter case built under the new order
was itself a form check — it patched a module attribute, and a rename with a leftover alias would
have left it counting zero for the wrong reason. Measured: **1 of 3 fell under that mutation, and
the counter case was not among them.** Its neighbour held it.

What found it was not a better rule. It was a lens from a **different model family** — the only one
of six — asked one question no Claude lens had been given: *what do five lenses of one family agree
not to see?* The witness had already named the risk (a homogeneous panel amplifies shared bias
rather than reducing it, arXiv:2505.19477); acting on that naming was a separate step and it is the
one that produced the finding. Register key: `VIERTE-INSTANZ-GEFUNDEN-ERST-VON-DER-FREMDFAMILIE-01`.

### S6 · A REQUIRED check is red because a wall-clock ceiling is a number from one machine — open, calibrated, not yet measured in CI

`coverage` is a required check under the branch ruleset, and it is RED on the frozen head. **This
entry exists because the finding would otherwise live only in the release record** — the exact gap a
lens of this round charged this file with, and repeating it here would be the same defect one round
later.

**Measured.** `renewal_work` costs 3.096 s at its largest allowed value on the CI runner, against a
ceiling of 3.0 s. In the parent's GREEN run the same axis measured 2.844 s — **94.8 % of the
ceiling**. On the reference machine it costs 1.44–1.56 s. The runner is uniformly about twice as
slow (`input_bytes` 1.8×, `json_nodes` 2.1×, `signatures` 2.5×, `data_digests` 2.0×), every other
axis carries a factor of ten in headroom, and this one carried 1.9×. **Nothing on this head touches
`renewal`** — the cause is the machine, not the candidate.

**Owner decision `OA-0646ecdf70`, option A with a cap**, implemented and measured locally: the
ceiling is expressed in reference units, a deterministic reference load is measured in the same run,
the machine factor is floored at 1.0 (measured on the reference machine: 1.0116), and the cap is
DERIVED from the smallest headroom of the other axes in the same run (measured: 19.54). Above the cap
the case reports NICHT MESSBAR with the factor, never green. Three cases bind the cap's derivation by
effect; replacing it with the constant that is correct today makes 2 of 3 fall.

**Why it stays open:** the calibration has NOT yet run in CI. Until a green `coverage` exists on a
head that carries it, this row is the reason the release does not land, and no local measurement
substitutes for that. **Funnel: no user of the shipped package is affected** — the DoS bound itself
is unchanged, only the way the ceiling is expressed. Register key:
`WANDUHR-LATTE-EINER-MASCHINE-AUF-EINER-ANDEREN-DURCHGESETZT-01`.

**The honest limit of the fix — and the first version of this paragraph was WRONG.** A ceiling that
scales with the machine can be stretched by a real cost increase up to the factor itself: with a
factor of 2, an increase must exceed 2× to be caught by THIS assertion. That much stood here already.
What followed was false: *"what catches a smaller one is the machine-independent half — the cost
curve's exponent and the work count."*

**It does not.** The cross-family lens refuted it and the refutation is arithmetic: a CONSTANT
multiplier leaves the log-log slope untouched, so the exponent cannot see it. Measured by computing
both: exponent 1.044646 before, **1.044646** after multiplying every point by 1.5 — difference
exactly 0.0. The work count is equally blind: it counts operations, and a per-operation slowdown
(a cache-miss regression, a slower hash path) changes none of them.

**So the gap is real and it is named as a gap, not as a covered case.** A cost increase between 1×
and the machine factor is caught by NOTHING in this file. On a runner with a factor of 2 that is a
doubling of the real cost passing green. The lens called it "an open hole, not an edge case", and
that is the honest description. What bounds it in practice is that the factor itself is bounded by
the derived cap — but that is a bound on the SIZE of the hole, not a closure of it.

Register key: `EINE-KOSTENSTEIGERUNG-UNTER-DEM-MASCHINENFAKTOR-FAENGT-NICHTS-01`.

**Why the wrong sentence is left visible rather than quietly replaced:** it was written in the same
round that spent its whole length removing claims stronger than their evidence, by the same hand, in
the entry that exists to state a limit honestly. A record that silently repairs its own overclaims
teaches nothing about how they get in.

### S7 · The calibration's own machine factor was frozen on its first measurement — CLOSED, caught by a lens on the fix itself

The fix for S6 carried a P0 that would have **reproduced the very failure it was built to remove**.
`_referenz_werte()` measured the reference load only `if not _REFERENZ_HIER:` — once per process. The
machine factor for the entire 1138-second run therefore hung on whatever the machine happened to be
doing at the moment of its first call.

**Measured, not argued.** With twelve foreign busy loops running: factor **1.2164**. After they
ended: still **1.2164** — the cached value. Cache cleared and re-measured on the now-idle machine:
**1.0098**. Ratio **1.205**.

The damage runs in **both directions**, and the second one is the worse: a load spike during the
first call loosens the ceiling for the rest of the run and hides real regressions; a quiet minute
tightens it and produces exactly the false red that owner decision `OA-0646ecdf70` exists to prevent.

**The first catch-proof for this was GREEN and therefore worthless**, and that is the more useful
half of the entry. It wrote values directly into `_REFERENZ_HIER` — bypassing `_referenz_werte()`
and with it the cache guard it claimed to bind. Announced 1 of 7 falling, measured 0. The second
attempt replaces the MEASUREMENT (`_cpu` and `_referenzlast`) instead of its result, counts the
measurements as a precondition, and falls with the message *"9 measurements on the first call, 0 on
the second"*. Announced 1 of 8, measured 1 of 8.

Fixing it broke **three existing cases of the same class** — they too had planted state instead of
walking the path, and had silently relied on nothing being measured after them. All four now go
through the measurement path.

**Cost of the fix, measured on this machine:** the test file goes from 55.44 s to 62.78 s, +7.33 s
(+13.2 %); against the full suite's 1138 s that is +0.64 %.

Nine mutations, nine announced numbers, nine hits — including the reinstated cache, which falls
exactly one case. Register keys: `MASCHINENFAKTOR-AUF-DER-ERSTEN-MESSUNG-EINGEFROREN-01` and
`FANGNACHWEIS-AM-SPEICHER-STATT-AM-PFAD-BEWEIST-NICHTS-01`.

### S7b · The first version of the S7 fix was itself refuted — by three lenses, on three different grounds

The fix recorded in S7 measured the reference load on every call but **appended** the measurements
and took the median over the whole run. Three independent lenses attacked that, and two of the three
attacks landed with arithmetic behind them.

**DRIFT (first lens, executed).** `_maschinenfaktor()` runs once per dimension, twelve times in a
run. With accumulation the first dimension sees 9 values and the twelfth sees 108 — axes of the SAME
run measured against different ceilings, decided by their position in a list.

**MASKING, the worse one (first lens, re-computed independently here).** A median only follows once
more than half the values are new; a slowdown starting at call *k* becomes visible around call
*2k-1*. For a real fivefold slowdown starting at call 11 of 12: the accumulated series reports factor
**1.000** for both affected dimensions, while a per-call series reports **5.000** immediately. The
ceiling would stay tight while the machine really is slow — the false red that `OA-0646ecdf70` exists
to prevent, hidden one level deeper.

**And the accumulation was not bound at all.** The same lens found the mutation that leaves all eight
cases green: a `clear()` at the start of the function. Every case cleared the series itself before
its own scenario, so none of them ever observed the behaviour across calls.

**The fix now measures a fresh series on every call and REPLACES the previous one.** Factor and
measured cost then describe the same time window — they are paired. Against the other danger, a
single restless series, the protection is no longer smoothing but `_faktor_spanne` (S7c).

**A second lens found a leak, executed rather than argued.** The test helper patched two module
globals in two separate statements, and every caller obtained the restore function only after the
call returned. The lens injected a failure between the two assignments and watched a case in a
DIFFERENT class inherit the fake clock and report a fabricated *"machine factor 20.00"* as a
clean-looking skip. Both globals are now set in a single `globals().update(...)` as the function's
last statement: either nothing is patched, or the function returned.

**The same lens showed the counter binds calls, not effect.** One extra unpaired call to the fake
clock desynchronises its start/stop alternation permanently, every measured delta collapses to 0.0 —
and `max(1.0, 0/reference)` yields exactly the 1.0 the median case expects. The case would stay green
on a completely corrupt measurement. The cases now assert that every measured value is positive and
that the outlier really is forty times the others.

**One deviation of my own, found by my own matrix and worth recording.** The case binding "the span
describes the SAME series as the median" measured that by the series' LENGTH. When the design changed
from appending to replacing, the length stopped growing — and the case went from catching that
mutation to catching nothing (announced 1, measured 0). It is now bound to the measurement COUNTER.
A riegel whose measured quantity turns under it is silent, and nothing says so.

**And a flaky assertion of my own.** The same case evaluated its last assertion AFTER restoring the
real clock, so it took a LIVE measurement of the machine inside a case that judges a faked series.
The same mutated state produced 2 failures in one run and 3 in the next. Moved inside the patched
window; ten runs of the mutated state now give ten identical results, and ten runs of the clean state
give ten times eleven green.

Register keys: `ANGEHAEUFTE-REFERENZREIHE-MASKIERT-DIE-SPAETE-VERLANGSAMUNG-01`,
`ZWEI-GLOBALE-IN-ZWEI-SCHRITTEN-GEPATCHT-LECKT-IN-FREMDE-KLASSEN-01`,
`EIN-ZAEHLER-ZAEHLT-AUFRUFE-UND-BINDET-KEINE-WIRKUNG-01`,
`RIEGEL-AN-EINER-MESSGROESSE-DIE-SICH-UNTER-IHM-WEGDREHT-01`.

### S7c · A bimodal machine silently loosened the ceiling tenfold — CLOSED, named by the cross-family lens

The median describes a machine well as long as it has ONE state. The cross-family lens named the
distribution where it fails exactly as the mean does: five of nine measurements slow, four normal.
The median then sits in the SLOW group, the ceiling follows it, and a factor of 10 passes unnoticed
because it stays below the derived cap of about 19.5. Measured across the range: up to four outliers
of nine the factor stays 1.000; at five of nine it jumps to 40.0 — the median's 50 % breakdown point,
in this construction and with real consequences.

**The closure needs no typed threshold**, which matters because the owner's decision forbids one. It
asks a sharper question than "how much does the machine vary": **does the verdict depend on which end
of the measured series you take?** If the cost lies between the ceiling at the fastest end and the
ceiling at the slowest, the measurement says nothing in either direction, and the case reports NICHT
MESSBAR. On a quiet machine that band is as narrow as the machine's own spread (1.046 on the
reference machine, and no real dimension fell into it in any run here); on a bimodal one it is as
wide as its jump.

Twelve mutations against the finished construction, twelve numbers announced before each run, ten
exact and two deviating by one case each — both named, both real catches, neither rounded away.

Register key: `EIN-ZWEIGIPFLIGER-LAUF-LOCKERT-DIE-LATTE-UM-SEINEN-SPRUNG-01`.

### S7d · Three mutants survived the entire class, and a fourth defect was in the test harness itself — CLOSED

The third lens ran mutations the class had never been asked about, and three of them left **all eight
cases green** while a real property was broken:

* **The axis-count multiplier was unreachable.** `_faktor_deckel` computes headroom as
  `(d.achsen * GRENZE_S) / k`. Removing the multiplier changed nothing, because every call in the
  class passed `ausser="renewal_work"` — and `renewal_work` is the ONLY dimension with `achsen != 1`.
  The one axis whose multiplier matters was always the excluded one. The new case excludes a
  single-axis dimension instead, so `renewal_work` enters the computation with its three axes.
* **The `k <= 0` guard was never exercised.** No fixture ever set a cost of zero. It becomes real as
  soon as an axis is cheap enough to fall under the clock's resolution; without the guard the cap
  dies on a division by zero, and a riegel that dies on an exception reports nothing at all.
* **The boundary `faktor > deckel` versus `>=` was undecided.** No fixture constructed equality. The
  boundary is a statement: the cap is the stretch at which the NEXT axis breaks, so exactly on it
  nothing has broken yet and the case is still measurable. Shifting it silently converts a measurable
  case into a NICHT MESSBAR, and a silent riegel is indistinguishable from a passing one.

**Building the third case exposed a defect in the harness rather than in the subject.** The fake
clock accumulated (`t += cost`), so the difference of two large floats was no longer exactly the
requested value; the drift pushed the factor just above the cap and the case went red for a reason
that had nothing to do with the boundary. Each measurement now starts at 0.0. A measuring instrument
whose own imprecision moves the quantity under test measures itself along with it.

Three mutations, three announced numbers, three hits. Register keys:
`DIE-EINZIGE-ACHSE-DEREN-MULTIPLIKATOR-ZAEHLT-WAR-IMMER-DIE-AUSGESCHLOSSENE-01`,
`EIN-SCHUTZ-DEN-KEINE-FIXTURE-ANSTEUERT-IST-UNGEBUNDEN-01`,
`DIE-GRENZE-EINES-RIEGELS-IST-EINE-AUSSAGE-KEINE-GESCHMACKSFRAGE-01`,
`EINE-AUFSUMMIERENDE-TESTUHR-VERSCHIEBT-DIE-GEPRUEFTE-GROESSE-01`.

### S10 · Four lines of the advisory matrix are red because three evidence artefacts bind a tree the candidate has overtaken — open, owner-gated on the signature

Measured by running the gate's own command in the full local clone rather than reading CI's verdict:
`python3 scripts/audit_candidate_matrix.py --json` → **28 PASS, 4 FAIL, 1 EXTERNAL_PENDING**.

The four failures are ONE class. `audit_artifacts/360/fuzz_soak_latest.json` (C6.2, C6.3) and
`audit_artifacts/360/rust_differential_matrix.json` (C8.2) bind commit `9e742bfa`. That commit IS an
ancestor of the frozen head — but the changes between it and here are not confined to the mutable
evidence paths, so the signature no longer covers this tree. C12.1 is the same shape one level up:
the pre-tag receipt binds `subject_tree_digest 877cd4f9`, this tree is `6c5be10e`.

**Why this cannot be closed here.** `scripts/sign_readiness_artifact.py` says it in its own words:
*"the release private key lives on the owner's machine, never on the build host."* The measurement is
mine to redo; the signature is not. Owner card `600_bereitschaftsartefakte_signieren` carries the
three options. What is prepared without a key: re-measure both artefacts on the final freeze head and
emit the canonical bytes (`--emit-payload` / `--context-out`), so signing is a single step.

**Two observations about the CI run, neither of which changes the verdict.** The job
`audit-candidate-matrix` checks out with the default depth (no `fetch-depth`, unlike the jobs at
lines 23 and 455), so in CI the bound ancestor is genuinely absent and the message reads *"does not
exist in this repository at all"* — a different sentence for the same correct FAIL. And the step
immediately before the check regenerates `rust_differential_matrix.json` via
`crosscheck.py --matrix`, whose writer emits no `version`, no `candidate` and no signature — so in CI
that check rejects an artefact the workflow itself just overwrote, and C8.2 can never pass there in
this form. Both are recorded as findings against the CI, not against the candidate:
`MATRIXJOB-KLONT-FLACH-UND-FINDET-DEN-EIGENEN-VORFAHREN-NICHT-01` and
`MATRIXJOB-ERZEUGT-DIE-DATEI-NEU-DIE-ER-DANACH-PRUEFT-01`.

**The first version of this entry was wrong and is left visible.** From the differing CI wording I
concluded the failure was a shallow-clone artefact — that the candidate was fine and CI merely could
not see the commit. Running the gate's own command locally refuted it in one line: the same three
checks fail here too, with the ancestor-is-not-evidence-only reason. The lesson is the one this cycle
keeps relearning: read the gate's verdict by running the gate, not by interpreting its message.

Register key: `DREI-BELEGE-BINDEN-EINEN-VORFAHREN-DEN-DER-BAUM-UEBERHOLT-HAT-01`.

### S8 · The reference load measures sha256 only, and six of the twelve axes are not hash-bound — open, NOT measurable on one machine

`_referenzlast()` is a pure sha256 loop. It was chosen deliberately — it must not be one of the axes
under test, or a real cost increase there could lift the machine factor along with it and hide
itself. That reasoning is sound and the choice stands. **What follows from it is a limit that was not
written down:** the factor describes how fast this machine hashes, and it is then applied to axes
whose cost is not hashing at all — `input_bytes`, `json_nodes`, `json_depth`, `string_len` (JSON
parsing), `int_bits` (big-integer arithmetic).

A machine whose SHA-256 is slow relative to its general speed — no hardware hash acceleration, a
different OpenSSL build — receives a factor above its true general-purpose factor, and the ceilings
of those six axes are loosened by the difference without anything noticing. The derived cap only
catches it once the inflated factor exceeds the smallest headroom of the other axes; below that it is
silent.

**Why this is recorded rather than fixed:** the size of the effect is a property of the DIFFERENCE
between two machines' instruction mixes. One machine cannot measure it — here both families run on
the same silicon and the ratio is 1.0 by construction. A number stated here would be a guess wearing
a measurement's clothes, and this file has spent its length removing exactly those. The mechanism is
readable in the code and is stated above; the magnitude is **NOT MEASURABLE** from this vantage
point.

Register key: `REFERENZLAST-MISST-EINE-FAMILIE-UND-SKALIERT-SECHS-ANDERE-01`.

### S11 · The reference load now measures TWO cost families, and the choice between them abstains — S8's loosening direction is closed, its magnitude still is not

S8 named the mechanism: the reference load is a pure sha256 loop, six of the twelve axes are not
hash-bound, and the factor is applied to them anyway. The cross-family lens on the frozen head
argued this can only produce a false RED, "because the factor only loosens". **Checked rather than
accepted, and it is wrong in one direction.** The factor is `hash_here / hash_ref`; axis A needs
`A_here / A_ref`. A false GREEN occurs exactly when the hash slowed down MORE than the axis — the
profile of a machine without hardware SHA: hash factor 3.0 against a true requirement of 1.5 leaves
the ceiling three times too loose for those six axes.

**So the family choice became a subject of its own abstention**, the same construction as the noise
band and again with no typed threshold. A second reference load `_referenzlast_hashfrei` (integer
arithmetic, no hashlib, calibrated to the same duration: n = 615 000, nine runs recorded on the
Farmer, median 0.06458 s, spread **1.012** against the hash load's 1.046) yields a second factor with
the same 1.0 floor. If the verdict differs between the two factors, the case reports NICHT MESSBAR:
this machine has a different cost profile than the reference machine, and then one family says
nothing about the six axes of the other. Where both families agree — the normal case on a machine of
similar profile — nothing changes.

**Measured on this machine.** Five quiet runs of the file: 122 passed, **0 skipped** in each — no
real dimension abstains in normal operation. That matters more than the mechanism: an abstention that
fires in the quiet case is not a protection, it is a silent riegel. Cost of the second series: the
file goes from 61.3 s to ~68 s, **+1.5 % of the suite**.

**Three properties came along with the duplicate and were bound only afterwards**, each catching
exactly ZERO before its own case existed (announced 0, measured 0, three times): the 1.0 floor of
the hash-free factor, its median-over-mean robustness, and replace-instead-of-accumulate. A property
that lives in the copied code is not bound by the original's case — the case calls a different
function. Catch-proofs: 1 of 15, 1 of 16, 1 of 17, each announced before the run.

**What this does NOT close.** The MAGNITUDE of a family mismatch is still not measurable from one
machine, exactly as S8 says: both families run on the same silicon here and their ratio is 1.0 by
construction. What changed is that a mismatch now produces an honest abstention instead of a silent
verdict in either direction. Register keys:
`EINE-FAMILIE-GEMESSEN-VIELE-SKALIERT-IRRT-IN-BEIDE-RICHTUNGEN-01`,
`EINE-KOPIERTE-EIGENSCHAFT-IST-NICHT-MITGEBUNDEN-01`.

### S12 · A calibration that scales a BOUND does not protect a SLOPE — found by a load probe, root cause in the estimator's own repetition policy

The ceiling is calibrated, the cap is derived, three abstentions are in place. A load probe of my own
(twelve foreign busy loops, `lastprobe.sh`) put the whole construction under exactly the condition
that made `coverage` fall on the previous head. Result:

```
quiet:  5 x  122 passed,   0 skipped
loaded:      118 passed,   3 skipped,  1 FAILED   (85.95 s)
```

The **three skips are the mechanism working**: machine factors 1.49 / 1.58 / 1.64 above the derived
cap of 1.13, reported as NICHT MESSBAR instead of a false red. The **one failure is the finding**:
`renewal_work: time exponent 1.31 > 1.2`.

**Why the calibration cannot catch it.** It scales a BOUND; the exponent is a SLOPE. S6 already
computed that a constant multiplier leaves the log-log slope exactly unchanged (1.044646 before and
after x1.5) — and that cuts both ways: what a constant factor cannot tilt, an UNEQUAL load can.

**The root cause is sharper than "unequal load", and it is in the estimator.** `_zeit_min` repeats a
measurement only while it stays below `WIEDERHOLEN_UNTER_S = 0.2`. Measured on the doubling series of
`renewal_work`:

```
n= 5000000  0.18084 s  REPEATED (minimum of 3)
n=10000000  0.35690 s  measured ONCE
n=20000000  0.70984 s  measured ONCE
n=40000000  1.43139 s  measured ONCE
```

The cheapest point gets a noise floor from three runs, the three expensive ones from one. Under load
a single sample inflates relatively more than a minimum-of-three, the ratio between consecutive
points grows, and the slope grows with it. **A slope estimator over unequally treated points is
biased by construction, not by chance.** For a bound the unequal treatment is harmless — each point
is judged on its own. For a slope it is not: a slope compares points with each other.

**The fix is the equal treatment, not a bigger number.** `_zeit_min_fest` takes the minimum of
exactly `WIEDERHOLUNGEN` runs regardless of cost, and the series records how often each point was
measured (`reihe_wdh`), so the property is bound by EFFECT: all four points of the curve must carry
the same repetition count. Deliberately scoped to the curve series only — `rand` and the ceiling
measurement keep their policy, because there every point is judged on its own.

**One methodological note against my own work.** The case first went red through a `KeyError` rather
than through its curated assertion — the same quality gap a lens charged an earlier case with. So the
measurement was instrumented first, then the case went red with the real message
(`UNTERSCHIEDLICH oft gemessen ([1, 3])`), then the fix. Announced 1 of 18, measured 1 of 18.

Register key: `EIN-STEIGUNGSSCHAETZER-UEBER-UNGLEICH-BEHANDELTE-PUNKTE-IST-VERZERRT-01`.
Ledger class 251.

### S13 · The cap was derived from the SAME measurement it judged — so it fell exactly when it was needed, and `coverage` went green by twelve abstentions

**The headline of the previous head was wrong, and a lens proved it with a position argument.** I
reported that `coverage` turned green because the ceiling is expressed in reference units. It turned
green because all twelve dimensions were SKIPPED.

```
88a5383:  3871 passed, 40 skipped, 0 failed
d3ca21f:  3861 passed, 28 skipped, 1 failed
skip delta: +12 = exactly the number of dimensions
```

The proof is not circumstantial: the sum of progress characters is 3911 = the collected count, so the
mapping is 1:1 per test item; the twelve `s` sit at positions 745–756, and `--collect-only` places
`test_kosten_am_limit_unter_der_obergrenze[input_bytes … renewal_work]` at exactly 745–756. Not one
instance passed. A skipped case is indistinguishable from a passing one from the outside — the silent
riegel this construction warns about, built by me and reported as success. The lens added a second
fact that makes it sharper: `renewal_work` measured **2.8098 s** in that run, already under the OLD
static 3.0 s ceiling. Runner variance alone would have sufficed; the calibration did not cause the
green outcome.

**Root cause, read from the code.** `_faktor_deckel` computed each headroom from the cost measured in
THIS run. Under load those costs rise, so the cap FALLS — while the machine factor RISES, because the
reference load slows down too. Both move toward each other, and `faktor > deckel` becomes true
exactly when the calibration is needed. Own load probe: quiet, factor ≈ 1.0 against cap 19.54 and no
skip in five runs; under twelve foreign busy loops, factor 2.4 against cap 1.30 and eight skips.

**Fix: the cap now comes from a RECORDING of the reference machine** (`_REFERENZ_FARMER_KOSTEN`, the
per-axis cost at the limit from a quiet Farmer run), not from the run under test. It stays derived —
no typed number — and becomes load-proof. The test helper is split accordingly: `_gefaelschte_messungen`
sets the CURRENT run's costs, `_gefaelschte_aufzeichnung` sets the cap's source. Faking both with one
handle would make the separation untestable, and the separation IS the fix.

**Measured after the change:** quiet 124 passed / 0 skipped; under load (factor 2.30–2.35 recorded
during the run) 113 passed / **11 skipped** / 0 failed — the eleven axes whose cap is 1.925, while
`renewal_work` with its cap of 7.949 stays measured. Announced 11, measured 11. Catch-proof against
the old source: announced 1 case, measured **5** — since the cap has its own source, five cases hang
on that separation instead of on one shared fake. Before the change the same mutation caught zero.

**And the number this uncovers belongs in the record, because it is not a bug but a property of the
cost model.** `renewal_work` has the smallest headroom of all twelve axes: 1.92 (1.5587 s against a
3 × 1.0 s ceiling). The next smallest is 7.95. So the derived cap is **1.925 for every axis except
renewal_work itself**, and the CI runner is documented ~2.0× slower. 2.0 > 1.925 — on that runner the
budget axis is structurally NICHT MESSBAR, not because of a feedback loop but because the cost model
has less headroom than the machine difference. Fixing the loop makes the abstention honest; it does
not make it rarer. Owner card `600_budgetachse_auf_ci_nicht_messbar` carries the three options.

Register keys: `EINE-ABSTENTION-MIT-SCHWELLE-AUS-DERSELBEN-MESSUNG-SCHWEIGT-WENN-SIE-GEBRAUCHT-WIRD-01`,
`DER-ABGELEITETE-DECKEL-IST-1925-UND-CI-IST-DOPPELT-SO-LANGSAM-01`. Ledger classes 253 and 256.

### S14 · Three guards were bound to the EXCEPTION their removal throws, not to the property they enforce — found by a foreign-family lens that refuted my own prediction

The cap of S13 is derived from a recording, and the derivation has a guard: an axis whose recorded
cost is zero contributes no headroom (`if k <= 0: continue`). I had a case for it, and the case was
red when I deleted the guard — so I filed it as bound. It was not. Deleting the guard throws
`ZeroDivisionError`; what the case bound was **that exception**, not the property.

A cross-family lens (qwen3.8:27b on un_turbov1) named the mutation that walks past it: `k = ...get(d.name, 0.0) or 0.0001`. No
exception, no skip, and **all nineteen cases of the class stayed green**. I had announced the
opposite — that the zero-cost case would fall — and I was wrong. The reason is sharper than the
lens's own: `or` replaces only the zero, whose headroom then becomes 1/0.0001 = 10000, and a
**minimum** cannot distinguish "skipped" from "present with an enormous value". The result is
identical either way; only the **participant list** differs.

Bound now by the list, not the result: `_DECKEL_BEITRAEGE` records which axes contributed, and the
case asserts a zero-cost axis is absent from it and counts the contributors. Counter-probe under
`or 0.0001`: **1 of 20 falls** (announced 1).

**The class swept, and it had two more members.**

*Neighbour A — an instrument written by two paths.* `_ZEIT_MIN_LAEUFE` reports how many runs stand
behind one curve point. `_messung` clears it, `_zeit_min_fest` writes it, `_messung` reads `[-1]`.
But `_zeit_min` — the edge-measurement path — wrote to the same list. That it never corrupted a
reading was a property of the **call order**, not of the code: the edge measurement happens to run
after the read. The lens named why no review catches it: as a module global it does not look like a
fault, it looks like a log. Fixed by giving `_zeit_min` its own `_RAND_LAEUFE`; catch-proof red
first on the unchanged code (announced 1 of 21, measured 1 failed / 20 passed), green after, and
the counter-probe falls again when the two are merged back.

*Neighbour B — an abstention that passes the assertion.* `_exponent` returns `nan` when no slope can
be formed. `nan` fails every comparison, so `nan <= EXPONENT_MAX` is false and the assertion goes
red — the correct, fail-closed answer. Nothing bound it. Measured: replacing `return float("nan")`
with `return 0.0` leaves **126 passed, twice, on an unloaded machine**; a zero passes as "linear or
better" through any ceiling. Now bound by a case over four degenerate series (no points, one point,
all costs zero, n not increasing): clean **127 passed**, under the mutation **1 failed / 126 passed**
(announced 1 of 127).

**A second measurement error of my own, in the probe that checked the reviewers.** I reported the
cross-family reviewer as unreachable. Only half of that was true: the rented card (`127.0.0.1:11435`)
answers `rc=000` and writes no file, but the GPU rig `192.168.178.117:11434` answers `rc=200` and
carries `qwen3-coder:30b` and `qwen2.5-coder:32b-instruct-q6_K`. What produced the false half was my
own loop: `curl` writes no output file on a failed connection, so the probe printed the model list of
the **previous** iteration under the dead endpoint's heading. Re-measured with `rm -f` before each
call: `rc=000`, no file. The health tile, separately, reads a surface file rather than the endpoints
(`inferenz_probe: "usable=2 warm=1 down=0 (surface 180s old)"`) and therefore still lists the dead
rented card as `WARM` — recorded against owner card `OA-a06a1de8c3`, not against this release.

**A measurement error of my own belongs in this section, because it nearly became a finding.** The
first run of neighbour B's mutation reported `1 failed, 125 passed` against my announced 0, and the
case that fell was the load-sensitive slope test of S12. I had been working in parallel — greps,
patches, a file port — while the timing-sensitive suite ran. The evidence was in the log all along:
**87 s against 74 s** in the clean runs. Re-measured with nothing else on the machine: mutated
126/126, clean 126/126. The mutation survives; the contradicting measurement was invalid. It was
also provably unreachable: the mutated line only runs on an empty slope list, and the failing axis
has four points with positive costs. A measurement measures the machine it runs on, including
whatever I am doing to that machine.

### S15 · Two of the cap's own guard tests went blind when I migrated the cap's source — found by review, not by the suite, and my sweep of the previous section had missed them

S14 closed three guards that were bound to an exception rather than to a property, and said the
class had been swept. **The sweep was incomplete, and the miss was mine.** S13 moved the cap's source
from the run's own measurement (`_MESSUNGEN`) to a recording (`_REFERENZ_FARMER_KOSTEN`). Two guard
tests kept faking the old source. Their fakery no longer reaches `_faktor_deckel`, so they ran
against the real recording and passed unconditionally:

- `test_EINE_reissende_achse_bringt_die_anderen_NICHT_zum_schweigen` defends the filter that keeps
  an already-torn axis from setting the cap for the others. Delete the filter — `if frei >= 1.0:` →
  `if True:` — and **21 of 21 cases stay green** (measured, then reproduced by me independently).
- `test_wenn_ALLE_achsen_reissen_wird_es_NICHT_still` defends the other edge: with every axis torn,
  the filtered list is empty and the fallback must be infinite, not 1.0, or twelve reds become
  twelve silences. Against the real recording the list is never empty (smallest headroom 7.95), so
  the fallback path is never entered. `return float("inf")` → `return 1.0`: **22 of 22 green.**

Three more gaps, all in cases written earlier the same day, all found by review and all reproduced
here before being fixed:

- The participant list bound only cost-zero, not the neighbouring exclusion `0 < headroom < 1.0`.
  Moving `_DECKEL_BEITRAEGE.append` out of the `if frei >= 1.0` block: **22 of 22 green.**
- The instrument case bound the **position** `[-1]`, not the separation of the two write paths.
  Writing from `_zeit_min` with `insert(0, …)` instead of `append(…)`: **22 of 22 green.**
- No fixture produced the third kind of degeneracy — costs falling to exactly zero while `n` keeps
  growing — so removing `k1 <= 0` from `_exponent`'s guard: **22 of 22 green.** That mutation does
  not return a wrong number; it raises `math domain error` where a non-number was required.

All four "before" states were re-measured by me, announced at zero fallen cases each, and all four
announcements held. After seven repairs the class is clean at 22 passed, and the counter-probes
fall: filter removed **3** (announced 2 — I forgot to count a precondition I had added myself in
the same round), `inf`→`1.0` **1**, `insert(0)` **1**, `k1 <= 0` **1**, append moved out **2**.

**The class one level up:** S14's class was "a guard bound to its exception rather than its effect".
This section's is "a guard pointing at a source the code no longer reads". A migration that changes
where truth comes from silently disarms every test that fakes the old place — and the suite cannot
say so, because a disarmed test is a passing test.

### S16 · The combination surface still judged in seconds while the single axes judged in reference units

Named as a side finding by the same review. Since OA-0646ecdf70 each single axis is judged against
`achsen * GRENZE_S * machine factor`, with a derived cap and three abstentions. `TestKombinierteAchsen`
was never carried along: it asserted `dauer <= achsen * GRENZE_S`, a number measured on the reference
machine. On a runner twice as slow that goes red because the machine is slow, not because the code
got more expensive — the exact defect this round was opened to fix, left standing on the other surface.

Catch-proof first, red on the unchanged code: a machine of factor 1.8 and a combination costing 1.5×
its reference bar — comfortably inside — was reported as **`ROT: renewal_ats_chain x int_bits: 3.000 s,
Obergrenze 2 x 1.0`**. After the change the bar reads `achsen * GRENZE_S * factor` with the same
derived cap (excluding no axis: a combination is not one of the recorded dimensions, so nothing can
bound itself). Class green at 22 passed; remove the factor again and exactly **1** falls.

**The first attempt at this catch-proof used factor 2.0 and got an abstention instead of a verdict:**
*"Maschinenfaktor 2.00 ueber dem abgeleiteten Deckel 1.92."* That is not a flaw in the case — it is
owner card `OA-dc37e26295` appearing a second time, on a second surface. The cap derived from the
recording sits at 1.925, and a CI runner at factor 2 cannot judge the combination surface either.
The fixture was moved below the cap; whether the cap belongs there is the owner's question, not
this test's.

### S17 · The machine factor was measured in a different time window than the costs it scales — and a real threefold regression walked through the gap, past all three abstentions

This is the heaviest finding of the round, and it was found by review with a **real** cost increase,
not by a mutation. A reviewer wrapped `renewal_work` in an additional calibrated sha256 burden —
real CPU cost, not a faked number in a dict — and ran the ceiling case five times on the shared
machine under ordinary ambient load. **Two of five runs passed silently.** No red, no abstention:
the derived cap, the cost-family check and the spread check all stayed quiet, because the defect is
not in any of them.

It is in the order. `test_kosten_am_limit_unter_der_obergrenze` calls `_messung(dim)` first — for
`renewal_work` that is many seconds of measurement — and only then `_maschinenfaktor()`. The factor
therefore describes the machine in a window that begins *after* the costs were measured. A load
spike falling into that late window loosens the bar without having touched the costs, and a real
regression fits underneath it. The reviewer observed the freshly measured factor swinging between
1.00 and 1.997 within minutes on the shared machine.

**I could not reproduce the swallow myself, and that is the expected result, not a refutation.** My
two runs with the same mutant both went red — at machine factor 1.000 both times, because I have
been deliberately keeping this machine quiet so that the round's other measurements stay valid. A
load-dependent gap cannot open on an idle machine. Reporting "could not reproduce" as if it
weakened the finding would have been the dishonest reading; the mechanism is visible in the source
order, and it is now bound deterministically instead of by a race.

**The repair puts a bracket around the cost measurement.** `_referenz_werte()` now runs both before
and after the expensive series, for both cost families, and both series are stored in the
measurement as `referenz_klammer`. The assertion judges that bracket instead of measuring afresh
afterwards. The bracket lives in `_messung`, not in the assertion, for a concrete reason:
`_messung` is cached, so if an earlier case already measured that axis, no time passes in the
assertion at all and a bracket there would enclose nothing.

With the bracket in place the **existing** third abstention does the work: if load hits only one of
the two windows, the series spans it, the verdict depends on which end you take, and that is
reported as NICHT MESSBAR instead of passing in silence.

Catch-proof, deterministic rather than racing: costs incurred in the quiet window (factor 1.0), bar
taken from the loud one (factor 3.2), costs sitting between the two bars. Against the old behaviour
— only the late window counts — the case falls: **1 failed, 67 passed** (announced 1). With the
bracket it is green.

**One question is deliberately left open for the owner, as card `600_latte_am_schnellen_ende_oder_abstinenz`.**
When the machine genuinely changes state mid-measurement, NICHT MESSBAR is the honest answer and red
would be a claim without ground — but OA-0646ecdf70 asks literally that a real cost increase *stay
red despite the factor*. Red is obtainable by always taking the bar at the **fast** end of the
bracket; that also tightens the bar on every machine by the reference load's own spread (1.046 on
the reference machine, about 4.6 %). Choosing between "no silent pass" and "always red" changes what
the gate means, and that is not a decision a test should make for its owner.

### S18 · Four of my own repairs each produced a new fault of the same class — and the only thing that improved was how loudly they failed

This section exists because the honest summary of the round is not the list of fixes. It is this
chain, and it is mine:

| What I built | How it broke | Who noticed |
|---|---|---|
| cap from the run's own measurement | went silent exactly under load | position proof — **passed silently** |
| cap from the recording | disarmed two of its own guard tests | review — **passed silently** |
| bracket around the cost measurement | six fixtures did not know the new mandatory key | full suite, `KeyError` — **failed loudly** |
| a flat replacement bracket | took five cases the very quantity they measure | class run, `ROT instead of SKIP` — **failed loudly** |
| bracket plus a fresh factor | measured the factor twice, from two windows | counter precondition, `27 instead of 9` — **failed loudly** |

The movement is the result, and it is not luck. It comes from the bindings that were added during
the day: the **participant list** instead of the result, the **counter** instead of the stored
state, the **bracket** instead of the later measurement, the **measuring field** instead of an
assumption. Each of them turned a class of silent pass into a loud failure. The fourth row is the
sharpest: repairing a fault of this class, I committed the same class again inside a single move —
I gave five cases a fixture whose fake no longer reached the property under test.

**The measuring field is not quiet, and no amount of discipline makes it so.** Measured while the
full suite ran: nine pytest processes from three origins at load 10.20 on 24 cores — my suite, my
own mutation shard from an earlier move, two runs from my own commit ceremony, and three from the
second operator account. `scripts/b7_messfeld.py` now reports that before a timing run and writes
it into the same log, with eight bound cases of its own; two of them bind the two mistakes the tool
made on its first real use (it read a tool directory as a foreign account, and counted a wrapper
and its child as two runs).

**What this means for the open owner card `600_latte_am_schnellen_ende_oder_abstinenz`:** option B,
taking the bar always at the fast end of the bracket, would fire false reds on this host regularly,
because the spread does not come from the code but from the neighbouring lane. That is an argument,
not an answer. Recorded as finding `600-MESSFELD-NICHT-RUHIG-HERSTELLBAR-01`.

### S19 · The owner decision was made executable — and building it showed it would have decided nothing

S17 leaves one question open for the owner: when the machine changes state mid-measurement, should
the bar stand at the fast end of the bracket (a real cost increase stays RED, as OA-0646ecdf70 asks
literally) or at the median (the spread abstention says NICHT MESSBAR)? Rather than leave that as
prose in a card, it is now one word in the code:

```python
LATTE_AUS_DER_KLAMMER = "median"            # way A — as measured
#                     = "schnellstes_ende"  # way B — stays red
```

Both readings are documented at the switch itself, with their prices: way B satisfies the owner's
wording, and tightens the bar on **every** machine by the reference load's own spread (1.046 on the
reference machine, ~4.6 %) — on this host, where nine pytest processes from three origins were
measured, that means regular false reds.

**The switch, as first built, was inert — and only the case that was supposed to bind it revealed
that.** The docstring named a test that did not yet exist; writing it was the correction of exactly
the class this whole document is about. On its first run it failed twice, for two different reasons,
and both are classes rather than incidents:

- **An abstention belongs to a policy, not to every policy** (ledger 262). The spread abstention
  asks "does the verdict depend on which end you take?". Way B answers precisely that by rule — so
  the abstention must not fire there. It did, and both switch positions reported NICHT MESSBAR. An
  open question was overruling a settled decision, invisibly, because both paths were green.
- **A comparison of two families only measures the families if both answer the same question**
  (ledger 263). With the hash factor taken at the fast end and the hash-free one still at the
  median, the cost-family abstention saw a flipping verdict and abstained — although both families
  described the same machine. It was comparing the formula, not the machine.

The case now runs the same situation twice, once per position, and insists the outcomes **differ**:
`"median"` → NICHT MESSBAR, `"schnellstes_ende"` → ROT. Without it, the card would have offered two
options with one outcome — a decision that decides nothing, with a clean rationale and no effect.

The default is not a recommendation. It is the state the measurement found.

### S9 · The one-second budget is a declared policy, not a derived number — open by design, named because it is load-bearing

`GRENZE_S = 1.0` carries the comment *"the declared upper bound: one second of compute at the largest
allowed value of ONE dimension"*. It is typed, and it is the only number in the construction that is.
The owner's requirement — *"the cap comes from the distribution of the runs, no typed number"* —
applied to the CAP, and the cap is derived. A declared budget may legitimately be a policy choice.

It is named here because it is **load-bearing and close to the edge**: `renewal_work` spans three
axes, so its ceiling is 3.0 s, and the CI runner measured 3.096 s. The red check that started this
whole entry is 3.2 % over a number nobody derived. A different declared budget would have produced a
different verdict about the same code.

Register key: `EINE-SEKUNDE-IST-EINE-ERKLAERTE-POLITIK-KEINE-MESSUNG-01`.

## Two owner cards landed in ONE move, and why they could not land separately (2026-09-08, `OA-133b901337` + `OA-dc37e26295`)

The budget cost surface asserts CPU time against a calibration measured on ONE machine
(Farmer, 24 cores, CPython 3.10.12). Two cards were open on it, and the owner answered both:

* **`OA-133b901337` → `schnellstes_ende`**, "valid on the reference machine, CI is exempt after
  the second answer." The lath now always stands at the FAST end of the reference bracket, which
  is what makes a real cost increase stay red despite the machine factor — the literal condition
  of `OA-0646ecdf70`. It also tightens the lath on every machine by the spread of the reference
  load (1.046 on the reference machine, so about 4.6 %).
* **`OA-dc37e26295` → "C, with a condition"**: mark the budget axis reference-machine-bound, skip
  it VISIBLY on CI with the MEASURED machine factor as the reason, measure it on the reference
  machine in the release bundle and carry it that way in the release report.

**They condition each other.** Landing `schnellstes_ende` alone would produce exactly the failure
mode both cards were raised against: on a runner that measures ~2x slower, a tighter lath turns
into red runs that say nothing about the code. Landing the binding alone would leave the lath at
the median, i.e. the state `OA-133b901337` was raised to end. Between the two there is an
intermediate state, and it is worse than either endpoint — so there is no intermediate commit.

**What "visibly skipped" means, and what it does not.** The skip carries its own vocabulary
(`UEBERSPRUNGEN`, `referenzmaschinengebunden`, the card number, the detected marker, the measured
factor) and deliberately shares NO word with the file's three other abstentions (cap, spread, cost
family — all of which say `NICHT MESSBAR`). That is not style. Every catch-proof in the file greps
for the WORDING of the abstention it hunts; a shared word would make it mistake this binding for
its own finding. Measured on 2026-09-08 with a build-host marker set: four cases fell visibly
BECAUSE the vocabulary differs, and two passed BLIND — they asserted only the ABSENCE of a text.
Both have since been sharpened to demand the verdict itself.

**Honest limit, three of them.**

1. The build host is recognised by a MARKER (`CI`, `GITHUB_ACTIONS`, `GITLAB_CI`, `BUILDKITE`,
   `JENKINS_URL` — the same tuple the signing path uses, and the equality is bound by a test), not
   by a machine fingerprint. A runner that sets none of them is treated like the reference machine
   and judges. That is deliberate: the alternative is to mute every unknown machine, and a mute
   guard cannot be told from a passing one. But it is an assumption about the environment, not a
   measurement.
2. The KOMBI surface takes its factor from a FRESH measurement after its costs were measured, not
   from a bracket around them. That is the same defect the bracket fixed for the single axes, still
   standing on the neighbouring surface. It is now reference-machine-bound like the single axes, so
   it cannot produce a false red on a runner — but on the reference machine its factor still comes
   from a different window than its costs. Named here rather than fixed in the same move, because
   the freeze head has to stay reproducible.
3. `median` remains in the code as the position the owner can return to in one word. It is not dead
   code and it is not the current verdict; both facts are bound by separate tests
   (`test_der_schalter_..._wirkt_wirklich` binds that the choice decides something,
   `test_die_OWNER_ENTSCHEIDUNG_zur_latte_steht_im_schalter` binds which way it fell).

**The finding I did not predict.** Under a build-host marker one case failed for a reason I had not
announced: it read `_DECKEL_BEITRAEGE` — a module global filled by `_faktor_deckel` — while the new
binding had skipped BEFORE that function ran. It was reading a foreign call's result and judging
over it. It fell this time; had the stale value happened to be the expected one, it would have
stayed green while attesting a computation that never happened. Fixed by stamping the instrument
with its owner and making it ownerless after one read (class 266 in the ledger).

**The CI skip is not free, and that is the price of the owner's condition.** `_messung(dim)` runs
BEFORE the binding fires, because the skip has to name the MEASURED machine factor — the card says
"with the measured machine factor as the reason, no typed number". A cheaper binding (skip before
measuring) would have to state a number it did not measure, which is exactly what the card
forbids. So on a build host the twelve dimensions are still measured; only the verdict is withheld,
and the measured factor is what the skip line reports.

### The other half of `OA-dc37e26295` is PREPARED, not DONE — and the attacker path got shorter

An adversarial lens on this very change (2026-09-08) established the following by grep over the
whole gate, and I verified each count myself:

* `grep -c budget_axis` over `scripts/audit_candidate_matrix.py`, `.github/workflows/` and the
  `Makefile`: **0**. The audit gate knows `_SOAK_ARTIFACT_REL` and `_DIFFERENTIAL_ARTIFACT_REL`
  and nothing else.
* `_ANKER_ROLLEN["readiness_und_register_signierer_600"]` authorises `{C6.2, C6.3, C8.2, C12.2}`.
  There is no check-ID for the budget axis, so the artifact cannot even be signed into the bundle
  the way the soak and the differential are.
* No CI job, no Makefile target and no script calls `scripts/budget_axis_measurement.py`.

So: **the CI half of the card is wired and measured; the reference-machine half is a script plus a
checklist line.** The release checklist entry added above IS the mechanism today, and a checklist
line is a person, not a gate. This repo names that exact anti-pattern in its own words at
`.github/workflows/ci.yml:149-152` — "a harness that only runs when a human remembers protects
exactly the round in which nobody remembers" — and this is the same shape, applied to this round's
own third piece of evidence.

**What that costs, concretely.** On CI the following still run: `test_die_last_erreicht_das_limit_
wirklich`, `test_l_minus_eins_l_und_l_plus_eins` (the DoS boundary itself), the time and work
exponents, both memory ceilings, `test_kombi_erreicht_jede_benannte_dimension` and the whole of
`TestProduktbudget`. What no longer runs there is the ABSOLUTE second ceiling, for twelve single
axes and seven combinations. An exponent is scale-invariant: a change that keeps the order linear
but multiplies the constant factor — three times more expensive `renewal_work`, exactly the shape
this file already caught once — passes the exponent test by construction. Before this change such
a regression had to survive a (noisy, but visible) CI red; now it has to survive nothing that runs
automatically. The attacker path is strictly shorter, and saying otherwise would be false.

**Why it is still the right change**: the CI reds were real and said nothing about the code, and
the owner decided. What is NOT decided is leaving the second half unwired. Wiring it means a new
check-ID in `audit_candidate_matrix.py` plus a role authorisation — a change to the release gate
surface itself, which is owner territory, not something to slip in beside a test fix. It is filed
as an open item rather than done quietly, and this paragraph is the honest state until it is:
**`OA-dc37e26295` is PARTIALLY implemented.**

**Owner decision on this gap (2026-09-08).** The owner accepted the reference half as a recorded
risk carried by the release-checklist line above, with the check-ID wiring in
`scripts/audit_candidate_matrix.py` scheduled AFTER the tag. So `OA-dc37e26295` is knowingly
PARTIAL for this release, not accidentally so — the difference matters: an accepted risk has an
owner behind it and a named next step; an unnoticed one has neither. The first half of the
condition is no longer only a script: measured on the reference machine on 2026-09-08 at 08:24Z,
quiet field before and after, `audit_artifacts/360/budget_axis_latest.json` says **12 axes passed,
0 skipped, 0 broken, machine factor 1.0, `ist_referenzmessung: true`, `ok: true`**.

---

## S20 — Ein Tor, dessen rote Zeilen der Kandidat selbst wegerklaeren darf

**Gefunden von einer FREMDEN Modellfamilie** (`qwen3.8:27b` auf un_turbov1, Rang 1, 2026-09-08),
die beauftragt war, mein eigenes Urteil ueber die vier roten Matrix-Zeilen zu widerlegen — und es
in drei von fuenf Punkten getan hat.

Der Einwand im Kern: ich hatte C6.2, C6.3, C8.2 und C12.1 als „Bindungsluecken, keine Defekte"
eingeordnet, mit der Begruendung, die Artefakte wuerden „bei der Buendelung neu erzeugt und dann
gruen". Das ist eine Aussage ueber einen Zustand, den es noch nicht gibt. Ein Release-Tor, an dem
der Kandidat selbst entscheiden darf, welche rote Zeile zaehlt, ist kein Tor — es ist eine
Meinung mit Farbe. Die Fremdfamilie nennt das Premature Closure; die Struktur ist dieselbe wie bei
jedem anderen Fund in dieser Datei: ein NICHT GEMESSENER Zustand traegt die Farbe eines gemessenen.

**Was daraus folgt und in dieser Runde umgesetzt wurde.** Das Uebergabeblatt vom 08.09. enthaelt
keine solche Vorhersage mehr, sondern die GEMESSENE Kette bis zur Signatur, Glied fuer Glied:
der Hook-Fix (28,3 s Laufzeit gegen ein Zeitfenster von 20 s, zweimal auf ruhiger Maschine
gemessen), das Lauf-5-Verdikt, die Gate-Zeile (`sign_readiness_artifact.py` weist den emit-Modus
ohne sie ab — woertlich gemessen, nicht angenommen), die Nutzlasten, die Owner-Signatur am Mac
(kein privater Schluessel auf dem Farmer, so im Release-Standard festgehalten).

**Was OFFEN bleibt.** Der Mechanismus fehlt weiterhin: nichts im Tor hindert einen kuenftigen
Kandidaten daran, eine rote Zeile erneut als „spaeter gruen" zu erklaeren. Ein Riegel dagegen
waere eine Aenderung an der Gate-Flaeche selbst und damit Owner-Gebiet, nicht etwas, das neben
einem Testfix mitlaeuft. Bis dahin traegt diese Zeile das Risiko, mit Owner dahinter und benanntem
naechsten Schritt — nicht unbemerkt.

## S21 — C6.3 verlangt einen 24-Stunden-Soak, den es zum Kandidatenkopf nicht gibt

**Gemessen.** `c6_3_full_24h()` liest `is_full_soak_24h` aus dem signierten Soak-Artefakt. Das
vorliegende Artefakt ist ein 300-Sekunden-Lauf und traegt dieses Feld auf `False`. Ein frischer
Kurzlauf am neuen Kopf aendert daran nichts: er ist die Evidenz, an der **C6.2** bindet, und laesst
C6.3 ehrlich auf DATA_BLOCKED statt auf PASS.

Der frische Lauf am Kopf `3962c771`: `ok: true`, 3 406 915 Iterationen ueber 63 Parser, 300,0 s,
`untriaged_crash_count 0`, `false_accept_count 0`.

**Owner-Entscheid 2026-09-08:** C6.3 ist benanntes Restrisiko. Der 24-Stunden-Soak laeuft parallel
(eigener Baum `pb_soak24h`, an `3962c771` gebunden, dirty 0), sein Ergebnis wird nachgetragen, und
er ist **kein Tor, das den Tag haelt**. Das ist eine bewusste Entscheidung mit Owner dahinter, kein
uebersehener Zustand — derselbe Unterschied wie bei S19.

## S22 — Rohmatrix und signiertes Differential-Artefakt tragen verschiedene Zahlen

**Gemessen am Kopf `3962c771` (2026-09-08).**
`audit_artifacts/rust_relation_differential_matrix.json` (unsigniert, ohne `produced_at`):
**39** Vektoren, 39 Zeilen, `all_agree: true`.
`audit_artifacts/360/rust_differential_matrix.json` (signiert, kandidatengebunden an den
ueberholten Commit `9e742bfa989e`): **42** Vektoren, 42 Zeilen, `all_agree: true`.

Die beiden sind nicht derselbe Stand, und C8.2 prueft `len(rows) == total_relation_vectors`
INNERHALB eines Artefakts — der Vergleich ZWISCHEN den beiden Dateien findet nirgends statt. Wer
die C8.2-Nutzlast aus der Rohmatrix neu erzeugt, senkt die Vektorzahl still von 42 auf 39, und
keine Pruefung meldet es. Vor dem Neuerzeugen ist zu klaeren, welche der beiden Mengen die richtige
ist. Dieselbe Klasse wie S20: eine Zahl, die faellt, ohne dass etwas sie vergleicht.

## S23 — Zwei Zweig-Commits, die der Kandidat NICHT hat, bringen ihm nichts — gemessen statt vermutet

**Owner-Entscheid 2026-09-08 (Karte `OA-ada920ee22`, Antwort 3C):** die zwei Commits bleiben
liegen; geprueft werden soll, ob sie dem Kandidaten etwas bringen. **Sie bringen nichts, und in
beiden Faellen traegt der Kandidat die haertere Fassung.** Das steht hier, weil ein „liegen
gelassen" ohne Messung spaeter wie eine Nachlaessigkeit aussieht.

**Ausgangslage, gemessen am Kopf `c08e4650`.** Der Zweig `probe/gatezeile-in-kandidat` traegt fuenf
Commits. Die Vorfahren-Pruefung je Commit ergibt: `c52884d` (codeql-113), `0aca175` (byte-freeze im
Bauweg) und `437dd32` (N11-Doku) sind **im Kandidaten**, `eb09cce` und `f67f289` sind es nicht.

**`eb09cce` (`tests/test_byte_freeze_zweite_haelfte.py`).** `xfail`-Vorkommen: **0 im Zweig, 0 im
Kandidaten** — der xfail, den der Commit-Betreff nennt, ist ohnehin weg. Der inhaltliche
Unterschied laeuft in die andere Richtung: die Zweig-Fassung macht aus JEDEM Fehlschlag einen
`pytest.skip`; der Kandidat unterscheidet **drei** Klassen (nicht messbar / Verletzung / **Werkzeug
defekt**) und benennt in seinem eigenen Kommentar den eingespeisten Fall, den die Zweig-Fassung
verschluckt haette: der `RuntimeError`, den `_build_wheel` wirft, wenn der Bau kein wheel
produziert — also ein ECHTER Baudefekt, der als `2 skipped` durchgegangen waere, mit stiller
Zusicherung UND stiller Anti-Paritaets-Kontrolle. Ein Merge haette diese Haertung zurueckgenommen.

**`f67f289` (`scripts/mutation_check.py`, `tests/test_mutation_isolation.py`).** Zweig 962 Zeilen
gegen Kandidat 1254. Die einzige Funktion, die nur der Zweig hat, ist `def sieben` — ein
`unittest.TestSuite`-Filter des ALTEN Mechanismus, den der Kandidat durch `_rote_aus_bericht`,
`_lauf_der_suite` und `_ausschluss_args` ersetzt hat. In `tests/test_mutation_isolation.py`
existiert **keine** Testfunktion nur im Zweig.

**Die Klasse dahinter, und warum sie hier wiederkehrt.** Der Kandidat-Kommentar sagt es selbst: die
Dreiteilung ist woertlich dieselbe, die `c52884d` am Go-Differential geschlossen hat
(`_beschaffungslage`: beschafft / nicht beschaffbar / Werkzeug defekt). Der Zweig fixte die INSTANZ
an einer Stelle, der Kandidat hat die KLASSE an beiden. Das ist der Grund, aus dem der aeltere
Zweig hier der schwaechere ist — nicht sein Alter, sondern seine Reichweite.

**Nebenbefund zu meiner eigenen Arbeit, weil er dieselbe Zeile betrifft.** Ich hatte vor dieser
Messung berichtet, `mutation_check._red_count` lese am Kandidatenkopf nie den `returncode`, und
daraus gefolgert, eine Abschlusszeile „0 Luecken" sei kein Beleg. Das war falsch: Zeile 719
uebergibt `proc.returncode`, Zeile 866 urteilt in der Reihenfolge Rueckgabewert, JUnit-XML, Text.
Ich hatte den Diff eines Zweigs gelesen, der diese Stelle fixt, und daraus auf den Zustand des
Kopfes geschlossen — **ein Diff ist eine Aussage ueber eine Differenz, nicht ueber einen Zustand.**
Aufgedeckt hat es eine Merge-Probe, die aus einem anderen Grund lief.

## S24 — C12.1 gehoert NICHT zu den drei Bindungsluecken, und meine Kettenbeschreibung war zu grob

**Was ich mehrfach berichtet hatte:** „vier rote Matrix-Zeilen, alle vier sind Bindungsluecken,
alle vier werden nach der Owner-Signatur gruen." Fuer C6.2, C6.3 und C8.2 stimmt das — es sind
Bereitschaftsartefakte, die der Owner am Mac signiert. **Fuer C12.1 stimmt es nicht**, und der
Unterschied ist keine Feinheit, sondern eine andere Art von Pruefung.

**Gelesen im Docstring von `c12_1_pretag_audit` (`scripts/audit_candidate_matrix.py`), der die
Owner-Entscheidung vom 2026-08-30 (Karte `OA-4a8daddb55`) woertlich traegt:**

> „A work branch is not finished and will get at least one more commit when it merges, so a receipt
> issued against it attests a tree that is about to stop existing. Producing one anyway would be
> exactly the act this check was built to catch — it would REPRODUCE the finding instead of closing
> it. C12.1 is a RELEASE gate; the receipt belongs to the tree that actually gets tagged."

Und weiter, zur Farbe auf einem Zweig:

> „So a red C12.1 on a branch is not unfinished work and not a tool defect. It is the check doing
> its job on an object it was not meant to bless."

**Folge fuer die Reihenfolge.** Der pre-tag-Receipt gehoert NICHT in die kanonischen Bytes, die
vor der Owner-Signatur emittiert werden. Er wird gegen den Baum erzeugt, der tatsaechlich getaggt
wird — also nach dem Merge. Wer ihn frueher erzeugt, tut genau das, was diese Pruefung faengt.

**Ehrlichkeitsmarke.** Dass C12.1 auf dem Tag-Baum dann gruen wird, ist die Aussage des Docstrings,
nicht meine Messung. Er belegt sie mit dem v5.0.0-Receipt
(`audit_artifacts/500/pre_tag_receipt_v5.0.0.json`, im Baum vorhanden, 1 KiB), der
`4212087273dc…` bindet; ich habe die Datei gefunden, aber **nicht nachgefahren**. UNGEPRUEFT mit
benannter Quelle.

**Die Grenze, die der Docstring selbst nennt und die hierher gehoert.** Der signierte
`audit_output_digest` des Receipts loest auf kein auffindbares Artefakt auf, und nichts in diesem
Tor loest ihn auf: „the field is signed, which makes it tamper-evident and attributable, not
checkable." Signiert heisst hier also zurechenbar, nicht geprueft — dieselbe Unterscheidung, die
S20 fuer das ganze Tor benennt.

**Warum dieser Abschnitt existiert.** Nicht wegen des Fehlers, sondern wegen seiner Form: ich hatte
vier rote Zeilen zu EINER Ursache zusammengefasst, weil sie gleichzeitig rot waren. Die
Fremdfamilien-Gegenlesung hatte genau das schon einmal angegriffen (S20, Punkt W3: „ist das
begruendet, oder ist 'alle vier haben dieselbe Ursache' eine bequeme Annahme?") — und ich hatte
ihre Frage damals mit einer Messung beantwortet, die nur DREI der vier betraf.

### S22, Nachtrag vom 2026-09-08: die Frage ist am Kandidatenkopf gemessen beantwortet — 42

S22 hielt fest, dass `audit_artifacts/rust_relation_differential_matrix.json` **39** Vektoren
traegt und `audit_artifacts/360/rust_differential_matrix.json` **42**, und dass niemand die beiden
Dateien vergleicht. Die offene Frage war, welche der beiden Mengen die richtige ist. Sie ist
gemessen, und zwar an der Quelle statt am Abzug.

**Der Erzeuger steht im signierten Artefakt selbst**, nicht unter `scripts/`: `producer.tool` =
`tools/pb_verify_rs/crosscheck.py`, `tool_version` 6.0.0, `produced_at` 2026-09-06T21:04:57Z. Dass
er unter `tools/` liegt, erklaert, warum eine Suche in `scripts/` nur Leser fand — `tools/` wird
aus dem sdist gepruned.

**Neu gefahren am Kandidatenkopf `c08e4650`** (`--matrix` ist opt-in, damit der normale Lauf nur
liest; Ausgabe bewusst AUSSERHALB des Baums, damit der Kandidat sauber bleibt):

    total_relation_vectors: 42
    rows:                   42
    all_agree:              true
    uneins:                 keine
    environment:            cargo 1.95.0 · rustc 1.95.0 · python 3.10.12

Und die Zusammenfassung des Laufs woertlich: „57/107 conformance-corpus case(s) reproduced
independently (incl. 42 relation vector(s) differentially, Python==Rust on exit-class + lineage)."

**Damit ist die Richtung klar.** Die 42 sind der Stand des Kandidaten, gemessen; die 39 stammen aus
einer Datei, die **kein `producer`- und kein `produced_at`-Feld traegt** — ein aelterer Abzug ohne
Herkunftsangabe. Wer die C8.2-Nutzlast aus der Wurzeldatei erzeugte, senkte die Vektorzahl still
von 42 auf 39; wer sie aus `crosscheck.py` erzeugt, misst sie.

**Was OFFEN bleibt, und es ist der eigentliche Punkt von S22.** Die Zahl ist jetzt geklaert, der
fehlende VERGLEICH nicht: nichts im Baum haelt die beiden Dateien gegeneinander, und C8.2 prueft
`len(rows) == total_relation_vectors` nur INNERHALB eines Artefakts. Ein kuenftiger Abzug ohne
Herkunftsangabe koennte dieselbe Verwechslung wieder ermoeglichen. Der Riegel dagegen ist derselbe
Bautyp wie `tests/test_register_population_gegen_restrisiko.py` — zwei erklaerte Flaechen
vergleichen statt eine aus der anderen abzuleiten — und gehoert in den ersten Zyklus nach dem Tag.

## S25 — GESCHLOSSEN (Owner-Entscheid 2026-09-08): die still unterdrueckte Ruecknahme

**Deep gate Lauf 5 auf `c08e4650`, Fund `L4-600-01`, P1, Jury 3/3 mit ausfuehrbarem Reproducer.**

> **STAND 2026-09-08, ~19:0xZ: GESCHLOSSEN.** Dieser Abschnitt stand hier zuerst als benanntes
> Restrisiko, weil die Owner-Regel dieser Runde lautet "Fix nur bei P0". Der Owner hat auf Karte
> `OA-dccd141d78` **gegen** diese Einordnung entschieden: *"Vor dem Tag schliessen: das stille
> continue durch `relation:malformed_successor` ersetzen, die drei Nachbarn im selben Durchgang
> mitziehen, parametrisierte Matrix position x malformation als Test — verzoegert den Tag um einen
> Bau- und Pruefzyklus."* Der Abschnitt bleibt stehen, weil ein geloeschtes Restrisiko keine
> Geschichte hat; was er beschreibt, ist ab hier der Zustand VOR dem Fix. Was jetzt gilt, steht
> unten unter "Wie es geschlossen wurde".

**Was passiert.** `relation.successor_warning` (`relation.py:471-473`) ueberspringt ein angehaengtes
Ziel, dessen EIGENER `relationships`-Block fehlerhaft ist, mit einem stillen `continue`. Erklaert
dieses Ziel eine Ruecknahme (`retracts` / `supersedes`) ueber das gepruefte Receipt, faellt die
Ruecknahme damit unter den Tisch: `safeForAutomation` kippt von false auf **true**, die CLI
`decision verify --policy --with-related` von exit 3 auf **0**. Der Spiegel in Rust
(`crates/pb_verify_rs/src/main.rs:1120-1122`) macht denselben Fehler.

**Warum das Differential es NICHT gefunden hat, und warum das hierher gehoert.** Python und Rust
stimmen ueberein — beide falsch. Der Python-Rust-Vergleich, sonst unser staerkstes Orakel, ist an
dieser Stelle blind; die Linse musste ein Orakel AUSSERHALB beider Implementierungen bauen. Das ist
dieselbe Anti-Paritaets-Lehre, die das Gate seit v2 fuehrt, hier zum ersten Mal an unserem eigenen
Kernversprechen.

**Die Klasse, nicht die Instanz.** Ein `continue`, das eine *present-and-wrong*-Struktur
ueberspringt, statt sie hart abzulehnen. Die Invariante steht im Repo schon (`L4-01`:
"present-and-wrong ist ein harter FAIL an JEDER Position") und ist an der Vorfahren-Position
korrekt umgesetzt (`relation:malformed_ancestor`) — nur an der Nachfolger-Position nicht. Drei
Nachbarn teilen sie: `decision.py:682`, `outcome.py:673`, `main.rs:1120-1122`.

**Wirkung, ehrlich abgegrenzt.** Kein Signaturbypass. Der Schaden ist, dass ein zurueckgezogenes
Receipt als automatisierungssicher gemeldet wird — und genau das ist die Aussage, wegen der jemand
dieses Paket einsetzt. Ich hielt es fuer den schwersten offenen Punkt der 6.0.0-Flaeche und empfahl,
ihn vor dem Tag zu schliessen; die Entscheidung lag beim Owner, und er hat sie so getroffen.

### Wie es geschlossen wurde

**Die Unterscheidung, auf die es ankommt.** Ein angehaengtes Receipt **ohne** `relationships`
schweigt weiter — es hat nichts erklaert. Eines **mit** einem unlesbaren Block meldet jetzt
`relation:malformed_successor` (Wire-Code `RELATION_MALFORMED_SUCCESSOR`) — es hat etwas erklaert,
das der Verifizierer nicht auswerten kann. Fail-closed heisst hier: eine nicht auswertbare
Erklaerung wird wie eine Ruecknahme behandelt, nicht wie ihre Abwesenheit.

**Ordnungsunabhaengig, und das ist kein Geschmack.** Eine LESBARE Ruecknahme gewinnt gegen die
unlesbare Meldung. Haenge das Verdikt an der Iterationsreihenfolge von `related`, koennte ein
Vorleger die praezise Aussage ("dieses Receipt ist zurueckgezogen") durch die unpraezise ersetzen,
indem er die Reihenfolge waehlt. Beide Sprachen waehlen daher den lexikografisch kleinsten
Kandidaten — noetig, weil Rusts `HashMap` bewusst randomisiert iteriert und Pythons `dict` die
Einfuegereihenfolge behaelt.

**Fangnachweis gegen `git HEAD`,** fuenf Faelle, genau einer aendert sich:

| Fall | ALT (HEAD) | NEU |
|---|---|---|
| ehrliche Ruecknahme | MELDET | MELDET |
| **Angriff (Ruecknahme + Fehler)** | **SCHWEIGT** | **MELDET** |
| kein Block | SCHWEIGT | SCHWEIGT |
| unverifiziert + malformed | SCHWEIGT | SCHWEIGT |
| malformed neben echter | MELDET (die echte) | MELDET (die echte) |

**Die drei Nachbarn.** `decision.py` (921 Zeilen) und `outcome.py` (979) wurden vollstaendig
gelesen: beide haengen an genau EINEM Aufruf von `successor_warning` und ziehen durch den Quellfix
mit — belegt als je ein End-to-End-Fall bis `safeForAutomation`, nicht als Annahme. Der
Rust-Verifizierer hat eine eigene Implementierung und wurde gespiegelt. *Pfadkorrektur:* die Karte
und der Text oben nennen `crates/pb_verify_rs`, im Baum liegt `tools/pb_verify_rs`.

**Der Fix aktivierte eine schlafende Divergenz — gefunden von einer Gegenlesung.** Bei explizitem
`"relationships": null` liefert `pred.get(...)` in Rust ein `Some(&Value::Null)`, in Python `None`.
Vor dem Fix uebersprangen beide Seiten still, der Unterschied war folgenlos. Sobald einer der Wege
etwas TUT, wird er zum Fund: Rust meldete, wo Python schwieg. Geschlossen mit `nested.is_null()`.
Das ist die unangenehme Haelfte von *fix the class* — ein Fix an EINER Seite kann eine bestehende,
folgenlose Asymmetrie in eine folgenreiche verwandeln.

**Gemessen.** Matrix `tests/test_stille_ruecknahme_position_x_malformation.py`: 4 Positionen x 9
Malformationen, 16 passed / 108 subtests, mit Vorbedingungspruefung je Malformation, fuenf
Anti-Paritaets-Richtungen und einem Meta-Test, der den ECHTEN Quelltext mutiert (die erste Fassung
prueste einen Nachbau und band nichts — auch das fand eine Gegenlesung). Regression ueber
relation/decision/outcome/rust-parity: 171 passed / 1 skipped. Vollsuite ueber den Stand:
**3947 passed / 24 skipped / 1062 subtests / RC=0**.

**Ehrliche Grenze, offen.** Ein ausfuehrbarer Paritaets-Vektor mit genau diesen Bytes
(`"relationships": null` gegen beide Verifizierer) fehlt noch; er gehoert in
`conformance/relation/generate_vectors.py::main()`, nicht als handgebautes Fixture — der Generator
erzeugt frische Schluessel, ein Lauf schreibt alle 43 Vektoren neu. Bis dahin ist die Gleichheit
der zwei Sprachen fuer DIESEN Fall am Code belegt und uebersetzt, aber **nicht gefahren**. Ebenso
offen und ungeprueft: `successor_warning` geht genau EINE Ebene ueber `related` — eine Ruecknahme,
die nur ueber einen zweiten, nicht direkt angehaengten Hop erreichbar waere, hat keine Zelle.

### Ein vierter Linsenfund derselben Runde, gemessen und ENTKRAEFTET

Eine Gegenlesung hielt fest, `successor_warning` gehe nur EINE Ebene ueber `related` und
uebersehe damit moeglicherweise eine transitiv erklaerte Ruecknahme. **Gemessen am 08.09.2026**
an einer dreigliedrigen Kette (C supersedes B supersedes A, A ist das gepruefte Receipt):

| angehaengt | Ergebnis |
|---|---|
| nur B | `superseded_by_attached` — gefunden, in EINEM Schritt |
| B und C | `superseded_by_attached` — gleich, C aendert nichts |
| nur C (B fehlt) | `None` |

**Es gibt keinen Abstieg, den man auslassen koennte.** `_load_related` (`cli.py:1779`) baut
`related` aus einer FLACHEN Pfadliste — ein Eintrag je `--with-related`, gekeyt am berechneten
content root. Jedes angehaengte Receipt ist damit unmittelbar Kandidat; die Schleife sieht ALLE,
nicht nur die vom Subjekt verlinkten. Die dritte Zeile ist keine Luecke, sondern die Grenze des
Materials: C sagt nichts ueber A, und was nicht angehaengt ist, kennt der Verifizierer nicht.
Diese Grenze steht bereits in `docs/predicates/relation.md`: Ziele werden OFFLINE angehaengt und
*never fetched*; eine wohlgeformte Kante ohne angehaengtes Ziel ist `DECLARED_UNRESOLVED` und
*explicitly NOT an error*.

Kein Fix, kein neuer Restrisiko-Punkt — der Fund ist mit einer ausgefuehrten Messung entkraeftet.
Er steht hier, weil eine still verworfene Gegenlesung von einer geprueften nicht zu
unterscheiden ist.

## S26 — `contentRootAlg`: ein vorhandener, aber unregistrierter Wert faellt still auf LEGACY zurueck

**Deep gate Lauf 5, Fund `L1-600-CRA-01`, P3, Jury 3/3.** Nicht gefixt, gleiche Begruendung wie S25.

`proofbundle.intoto._declared_content_root_alg` prueft den Rohwert mit einer str-engen Wache. Ein
**vorhandener** Wert, der kein String ist (`""`, `0`, `True`, `[]`, `{}`, `null`), faellt dadurch
in den Abwesenheitszweig und damit auf den LEGACY-Algorithmus — `ok=true`. Eine unbekannte
**String**-Kennung geht eine Zeile weiter korrekt fail-closed. Abwesenheit und
vorhanden-aber-falschtypig werden also verwechselt.

**Ehrliche Abgrenzung, die in den Befund gehoert:** `contentRootAlg` liegt INNERHALB der signierten
Nutzlast. Das ist kein Signaturbypass. Der Schaden ist, dass das Urteil signierten Inhalt falsch
beschreibt, dass ein vertraglich abzulehnendes Receipt akzeptiert wird, und dass ein strengerer
Fremdverifizierer bei identischen Bytes anders urteilt.

**Klasse:** `(Feld ABWESEND) == (aufgeloester Algorithmus == LEGACY)` muss streng gelten; ein
vorhandener, nicht registrierter Wert muss fail-closed enden. Betrifft jedes Algorithmus- oder
Selektorfeld, das aus geparstem Inhalt gelesen wird, in beiden Sprachen.

## S27 — Der sdist-Bau traegt einen Cache, der eine gestrichene Zeile ueberlebt

**Gemessen am 2026-09-08, zweimal gebaut, EIN Unterschied.** Mit vorhandenem
`src/proofbundle.egg-info/` enthaelt das sdist `scripts/budget_axis_measurement.py` (35 Dateien
unter `scripts/`); mit beiseitegelegter `egg-info` nicht (34). `SOURCES.txt` fuehrte die Datei in
Zeile 452; setuptools SCHREIBT diese Liste neu, ENTFERNT aber vorhandene Eintraege nicht.

**Folge, und sie ist die eigentliche Gefahr:** eine aus `MANIFEST.in` GESTRICHENE Zeile wirkt in
einem schmutzigen Arbeitsbaum erst nach dem Leeren des Caches. Ein Release-Bau von Hand koennte
damit genau die Skripte ausliefern, die der Owner-Entscheid zu `OA-8b1a31cc4f` ausgeschlossen hat —
darunter die zwei, die einen privaten Schluessel LESEN. Der CI-Weg ist nicht betroffen (frischer
Checkout), der Handweg schon.

`scripts/build_reproducible.py` raeumt `egg-info` nicht (gemessen: 0 Treffer). Der Riegel dagegen
gehoert in den Bauweg, nicht in eine Notiz — er ist NICHT gebaut, und das steht hier als offener
Punkt, nicht als erledigt.

## S28 — Der Klassen-Ledger des Gates lief ueber 48,5 % seiner Klassen

Der Pre-Sweep von Lauf 5 meldet `pass` — ueber **95 von 196** gelernten Klassen, Deckung 0,4847,
`0 unexplained`, `0 regressed`. Woertlich heisst das: fuer **101 Klassen liegt aus dieser Runde
kein Nichtregressions-Nachweis vor**. Ein `pass` bei knapp der Haelfte ist eine Aussage ueber die
abgespielte Teilmenge, nicht ueber den Ledger. Das Gate selbst schreibt diese Grenze in sein
Ergebnis; sie wird hier uebernommen, damit sie nicht in der Zusammenfassung verschwindet.

## S29 — Der Wegwerfbaum der Zahlenbindung stellt seine eigene Vorbedingung her

**Adversariale Gegenlesung 2026-09-08, ausgefuehrt belegt.** Die im Kopf von `tests/conftest.py`
genannten Skip-Zahlen **34** und **9** sind gebunden — gemessen in einem Wegwerfbaum, den
`tests/test_paketgrenze_zahlen_sind_abgeleitet.py::_wegwerfbaum` aufbaut. Dieser Baum kopiert
`scripts/fork_pr_secret_isolation.py` und `scripts/pre_tag_audit_gate.py` **immer** mit hinein,
unabhaengig davon, ob `MANIFEST.in` sie noch ausliefert.

**Was daran offen ist.** Verlaesst eines der beiden die Auslieferungsliste, misst die Bindung
weiterhin 34 bzw. 9 SKIPS — waehrend die ECHTE Auslieferung an derselben Stelle etwas anderes tut.
Die Zahl bliebe richtig und beliefe etwas anderes. **Genau dieses Muster ist in dieser Runde einmal
eingetreten:** `scripts/budget_axis_measurement.py` stand einzeln in `MANIFEST.in` und verliess die
Liste am 08.09.; beide hier genannten Skripte stehen ebenfalls einzeln darin.

**Warum es NICHT P0 ist:** heute sind beide ausgeliefert, die Zahlen stimmen, gemessen. Nach der
Owner-Regel dieser Runde (Fix nur bei P0) bleibt es benanntes Restrisiko.

**Die Klasse:** ein Messaufbau stellt seine Vorbedingung selbst her, statt sie von der Quelle zu
uebernehmen, die sie im Ernstfall bestimmt — dann misst die Bindung ihre eigene Annahme. Der
Vorschlag ist entsprechend nicht "mehr kopieren", sondern: nur kopieren, was `MANIFEST.in`
ausliefert, und sonst **NICHT MESSBAR** melden statt eine Zahl zu bestaetigen, die nichts belegt.

## S30 — Zwei Grenzen des Import-Riegels, die am Artefakt nicht entscheidbar sind

Der Riegel gegen den Sammelabbruch (Fund `L6-600-01`, gefixt) hat zwei benannte Grenzen. Beide
stammen aus adversarialen Gegenlesungen mit ausgefuehrten Faellen, beide sind **nicht** durch
Nachbessern schliessbar, und beide stehen deshalb hier statt in einer Zusicherung.

**(1) Ein TIPPFEHLER im Pfad sieht aus wie eine nicht ausgelieferte Datei.** Verlangt ein Modul
beim Import `scirpts/mutation_check.py` statt `scripts/…`, fuehrt die Dateiliste der Verteilung
diesen Pfad nicht — also gilt die Abwesenheit als Absicht, und das Modul wird uebersprungen statt
laut zu fallen. Am Artefakt allein ist das nicht zu unterscheiden: „die Verteilung trug es nie"
und „der Code fragt nach dem Falschen" ergeben denselben Befund. **Was dagegen steht:** das
Ueberspringen ist NICHT still — die Zusammenfassung nennt Modul und fehlende Datei. Ein Leser
sieht es; ein CI-Lauf wird davon nicht rot. Wer das schliessen will, braucht eine Aussage
AUSSERHALB des Artefakts, etwa eine gepflegte Menge erwarteter Uebersprungen — und die veraltet
still, sobald die Suite waechst (dieselbe Klasse wie
`ZAHL-IM-STANDARD-VERALTET-STILL-WENN-DIE-LISTE-WAECHST-01`).

**(2) Ein `conftest.py` in einem UNTERverzeichnis von `tests/` ist nicht abgedeckt.** pytest laedt
solche Dateien ueber `_importconftest`, einen anderen Weg als `pytest_pycollect_makemodule`; ein
Importfehler dort bricht das Sammeln unveraendert ab. **Gemessen am Kandidaten:** es gibt genau
EIN `conftest.py`, `tests/conftest.py`, und die Dateiliste des sdist fuehrt genau dieses eine. Die
Luecke ist also latent, nicht lebend — sie wird es in dem Augenblick, in dem jemand ein zweites
`conftest.py` unterhalb von `tests/` anlegt, das eine nicht ausgelieferte Datei anfasst.

**Warum beide hier stehen und nicht als Fix:** die erste ist am Gegenstand nicht entscheidbar, die
zweite hat heute keinen Gegenstand. Ein Riegel gegen etwas, das es nicht gibt, ist ungetestet und
damit selbst eine Behauptung.

**(3) NACHTRAG 08.09.2026 — die dritte Grenze war keine, sondern ein Defekt, und ist gefixt.**
Eine fremdfamiliaere Gegenlesung (qwen, lokaler Host) fragte nach Namespace-Paketen: seit
Python 3.3 ist ein Verzeichnis OHNE `__init__.py` ein gueltiges Paket, und dieser Baum fuehrt zehn
davon (`scripts/`, `tests/`, `conformance/`, `tools/…`). Die Formenliste des Riegels kannte nur
`pkg.py` und `pkg/__init__.py`.

An einem gebauten Fall gemessen: bei VORHANDENEM `scripts/` und bei GANZ FEHLENDEM `scripts/`
antwortete der Riegel identisch — er meldete beide Male `scripts/__init__.py`, einen Pfad, den ein
Namespace-Paket nie hat. Im ersten Fall war die Antwort schlicht falsch. Behoben: das Verzeichnis
ist als dritte Form aufgenommen (`(wurzel / stamm).is_dir()`), Fangnachweis 1 von 19 rot, angesagt
und getroffen.

Bemerkenswert an der Herkunft: eine Claude-Linse hatte zwei Stunden vorher die INSTANZ derselben
Klasse gefunden (ein fehlendes Symbol in einer vorhandenen Datei), der fremdfamiliaere Reviewer
den NACHBARN. Die verletzte Annahme ist in beiden Faellen dieselbe — "ein Modul existiert in genau
den Formen, die ich aufgezaehlt habe" — und die Aufzaehlung war jedes Mal das Problem, nicht ihre
Reihenfolge.

**Die VIERTE Form bleibt eine echte Grenze:** Erweiterungsmodule (`.so`, `.pyd`) erfuellen ebenfalls
keine der drei Formen. Gemessen fuehrt dieser Baum keine (`find` ueber den ganzen Baum, ohne
`.venv` und `target/`: null Treffer), weshalb sie hier benannt statt verdrahtet ist — ein Riegel
gegen etwas, das es nicht gibt, ist ungetestet und damit selbst eine Behauptung. Der von der
Gegenlesung vorgeschlagene Ausweg ueber `importlib.util.find_spec` traegt nicht: scheiterte der
Import, findet `find_spec` das Modul auch nicht.

**(4) NACHTRAG 08.09.2026 spaet — die VIERTE Form ist gemessen und faellt durch, hat hier aber
keinen Gegenstand.** Nachdem das Verzeichnis als dritte Form aufgenommen war, blieb die Frage, ob
die Liste jetzt vollstaendig ist. Sie ist es nicht: ein Modul in einem `.zip` auf `sys.path`
(zipimport, seit Python 2.3) erfuellt WEDER `pkg.py` NOCH `pkg/__init__.py` NOCH
`(wurzel / stamm).is_dir()`.

GEMESSEN an einem gebauten Fall: `importlib.util.find_spec` findet das Modul im Archiv
(`zip_import_moeglich: True`), und `_fehlende_datei_aus` meldet trotzdem
`scripts/gepacktes_modul.py` als fehlend. Die Formenliste ist also weiterhin unvollstaendig — die
Klasse `aufzaehlung_statt_existenzfrage_bindet_nur_die_listeneintraege` steht im Klassen-Ledger des
deep gate zu Recht als `class_open`.

**Warum trotzdem kein Fix:** `find` ueber den ganzen Baum (ohne `.venv` und `target/`) ergibt
**null** `.zip`/`.egg`. Die Form hat hier keinen Gegenstand, und ein Riegel gegen etwas, das nicht
vorkommt, ist ungetestet — dieselbe Enthaltsamkeit wie bei `.so`/`.pyd` oben und beim negativen
Sweep ueber `_REPO_ONLY_MARKERS` (68 Worktrees, jeder traegt alle drei Marker). **Der Sweep
entscheidet, nicht die Aehnlichkeit der Bauart.** Der Entwurf des fehlenden Meta-Tests liegt
bereit; gebaut wird er, sobald eine Auspraegung im Baum vorkommt.

## S31 — Der Riegel „stammt der Korpus aus seinem Generator" deckt EINEN der zwei Korpusse

`tests/test_korpus_stammt_aus_seinem_generator.py` haelt eine teuer bezahlte Klasse fest: **eine
Aenderung am erzeugten Artefakt statt an seiner Quelle ist unsichtbar und wird beim naechsten
Generatorlauf verworfen.** Der Test erzeugt den Korpus daneben, vergleicht bytegenau, und prueft
zusaetzlich, dass das Manifest genau die Faelle nennt, die es auf der Platte gibt.

Er tut das ausschliesslich fuer `conformance/agent_review` (Zeile 32: `KORPUS = REPO /
"conformance" / "agent_review"`). Fuer `conformance/relation` — derselbe Aufbau, eigener Generator
`conformance/relation/generate_vectors.py`, eigene Eintraege im selben Manifest — gibt es ihn
nicht.

**GEMESSEN am 08.09.2026**, indem seine drei Pruefungen einmal von Hand gegen den relation-Korpus
gefahren wurden (Generator in eine Kopie daneben, dann verglichen):

| Pruefung | agent_review | relation |
|---|---|---|
| jeder Fall auf der Platte stammt aus dem Generator | verdrahtet | **8 Faelle nicht** |
| Korpus bytegenau = Generatorausgabe | verdrahtet | nicht gemessen (Schluessel je Lauf frisch) |
| Manifest nennt genau die Faelle auf der Platte | verdrahtet | von Hand: stimmt (44 = 44) |

Die acht: `statement-malformed`, `statement-retracts-declared-unresolved`,
`statement-retracts-unauthorized`, `statement-retracts-verified-blocked`,
`statement-retracts-verified-visible`, `statement-supersedes-verified`,
`target-subject-ambiguous`, `target-subject-missing`. Ein Neulauf von `generate_vectors.py`
erzeugt sie nicht; sie laufen im differentiellen Vergleich mit (44 von 44 gruen), aber ihre Quelle
ist heute die Platte selbst.

**Warum das hier steht und nicht gefixt ist.** Der Riegel auf `relation` auszuweiten faellt nicht
billig aus: er waere ab der ersten Zeile rot, und gruen wuerde er erst, wenn diese acht Faelle in
den Generator zurueckgeschrieben sind — Arbeit an acht handgebauten DSSE-Vektoren, mitten in der
Release-Linie. Die Owner-Regel dieser Runde lautet „Fix nur bei P0", und P0 ist es nicht: der
Korpus ist heute konsistent (Manifest == Platte, 44/44 differentiell gruen). Was fehlt, ist der
Schutz gegen die naechste Handarbeit daran.

**Die Klasse ist die des Tages:** eine Bindung bindet nur, was sie ANFASST. Der Riegel ist nicht
falsch, er ist schmal — und seine Schmalheit ist an keiner Stelle sichtbar, weil er unter einem
Namen steht, der allgemein klingt. Registerschluessel
`RIEGEL-DECKT-EINEN-VON-ZWEI-GLEICHGEBAUTEN-KORPUSSEN-01`.

## S32 — `errorContains` prueft nur EINE der beiden Implementierungen, und der Korpus sieht aus, als pruefe es beide

Gefunden von einer Gegenlesung am 08.09.2026 beim Eintragen der zwei Paritaets-Vektoren.

Ein Konformanz-Fall kann in `expected` ein Feld `errorContains` deklarieren — zehn Vektoren tun
das heute, zuletzt `relation-malformed-relationships-successor` mit
`RELATION_MALFORMED_SUCCESSOR`. Es liest sich wie eine Zusicherung ueber den Fall.

**Gemessen ist es das nur halb.** `conformance/run_conformance.py:272-275` prueft den String gegen
Pythons eigenen Bericht und stderr — dort wirkt er. `conformance/common_vocabulary.py:131-144`
(`expected_label`) liest das Feld **gar nicht**: das gemeinsame Vokabular kennt nur `exitClass`,
`lineage` und `policyVerdict`. Der differentielle Vergleich in `tools/pb_verify_rs/crosscheck.py`
laeuft ueber genau dieses Label — und Rusts `verify-relation` gibt ohnehin nur `{"lineage": …}`
aus, koennte den String also nicht fuehren, selbst wenn jemand ihn dort suchte.

**Die Folge, die zaehlt:** trifft der Rust-Verifizierer dieselbe Exit-Klasse aus einem VOELLIG
ANDEREN Grund, faellt das nirgends auf. Der Vektor belegt dann „beide sagen POLICY_UNMET", nicht
„beide sagen POLICY_UNMET WEIL der Nachfolger unlesbar ist". Fuer den aktuellen Stand ist das
folgenlos — die Quelltexte (`relation.py` und `main.rs`) wurden gelesen und sind an dieser Stelle
spiegelgleich —, aber der Beleg dafuer ist die Lektuere, nicht der Korpus.

**Warum nicht gefixt:** die ehrliche Loesung ist ein Grund-Feld in Rusts JSON-Ausgabe plus eine
vierte Achse im gemeinsamen Vokabular. Das ist eine Erweiterung des Konformanz-Vertrags mitten in
der Release-Linie und faellt unter die Owner-Regel „Fix nur bei P0". Registerschluessel
`ERWARTUNG-PRUEFT-NUR-EINE-VON-ZWEI-IMPLEMENTIERUNGEN-01`.

**Ein zweiter, kleinerer Befund derselben Gegenlesung** gehoert daneben: die Beweiskraft des
Vektors `relation/null-relationships-successor` haengt VOLLSTAENDIG an seiner `policy.json`.
Gemessen mit einem absichtlich kaputten Rust-Build: mit `--policy` weichen die Verifizierer ab
(exit 0 gegen 3), ohne `--policy` sind beide exit 0 und der Defekt ist unsichtbar. Der Fall
deklariert die Policy, und `run_conformance.py::_check_relation` wie `crosscheck.py::_relation_argv_common`
reichen sie nachweislich durch — heute also verdrahtet. Wer diese Verdrahtung einmal loest, macht
den Vektor still wertlos, ohne dass ein Test rot wird.

## S33 — Der Vollstaendigkeits-Check des Budget-Belegs vergleicht sich mit sich selbst

Gefunden von einer Gegenlese-Linse am 09.09.2026, von mir am Code und an einem ausgefuehrten Fall
nachgeprueft. Er betrifft `scripts/budget_axis_measurement.py`, den Schreiber des dritten
Bereitschaftsartefakts (`OA-dc37e26295`).

**Was das Artefakt ueber sich behauptet.** Sein `note`-Feld sagt woertlich, eine LEERE Achsenliste
mache `ok=false`, denn „`all()` ueber nichts ist wahr, und ein gruener Beleg ueber null Messungen
ist die stillste Luege von allen". Der Kommentar bei `achsen_erwartet` begruendet zusaetzlich, warum
dort keine getippte Zahl steht: „eine Zahl allein ('12') waere wieder eine getippte Erwartung".
Beide Saetze sind richtig — und die gewaehlte Abhilfe traegt weniger weit als sie.

**Gemessen.** Zeile 158 prueft
`[a["name"] for a in achsen] == [d.name for d in t.DIMENSIONEN]`. `achsen` wird unmittelbar davor
durch `for dim in t.DIMENSIONEN` GEBAUT. Der Vergleich kann also nur anschlagen, wenn die Schleife
selbst etwas ueberspringt — nicht, wenn `DIMENSIONEN` bereits verkuerzt ist. Zeile 154
(`achsen_erwartet`) speist sich aus derselben Liste, das Artefakt nennt seine Sollmenge also
ebenfalls aus der Quelle, die der Fehler treffen wuerde.

Die Linse hat es ausgefuehrt: die teuerste Achse `renewal_work` aus `DIMENSIONEN` entfernt, Ergebnis
**`ok=True`**, kein rotes Signal, kein Hinweis im Beleg. Der LEERE Fall ist abgefangen, der
VERKUERZTE nicht.

**Eine unabhaengige Quelle existiert und passt genau.** `src/proofbundle/budget.py:184`
(`class VerificationBudget`) traegt zwoelf Felder — `data_digests`, `disclosures`, `input_bytes`,
`int_bits`, `json_depth`, `json_nodes`, `merkle_path`, `renewal_ats_chain`, `renewal_work`,
`signatures`, `string_len`, `witnesses` — eins zu eins namensgleich mit den zwoelf Achsen. Gegen
diese Menge zu pruefen waere eine Fremdpruefung statt eines Selbstvergleichs.

**Warum nicht gefixt.** Fuer den Kandidatenkopf ist der Pfad nicht aktiv: alle zwoelf Achsen sind
vorhanden und bestanden, unabhaengig per pytest bestaetigt. Kein Falsch-Gruen heute. Nach der
Owner-Regel dieser Runde („Fix nur bei P0") faehrt es als benanntes Restrisiko mit. Der Fix braucht
ausserdem seinen eigenen Meta-Test — eine Achse entfernen und ROT erwarten —, sonst waere der neue
Riegel wieder nur eine Behauptung.

**Die Klasse:** ein Pruefer, der seine Sollmenge aus der Istmenge ableitet, prueft nichts.
Registerschluessel `VOLLSTAENDIGKEITS-CHECK-DES-BUDGET-BELEGS-VERGLEICHT-SICH-MIT-SICH-SELBST-01`.

**Dieselbe Klasse traf in derselben Nacht meinen eigenen Feldvergleich, und das gehoert daneben.**
Die Commit-Botschaft von `21669b6` sagt „Feldvergleich ueber ALLE Felder ausser Zeit und Maschine:
keine einzige Abweichung". Das ist falsch. Dieselbe Linse verglich ausnahmelos Blatt fuer Blatt und
fand **58** abweichende Felder; nachgerechnet: 12 `exponent_zeit`, 12 `kosten_am_limit_min_s`,
11 `kosten_am_limit_max_s`, 9 `referenzlast_hier_s`, 7 `dauer_max_s`, **6 `speicher_peak_bytes`**
(Bytes, weder Zeit noch Maschinenfaktor) und 1 `produced_at_measured`. Mein Vergleich hatte
`achsen` und `kombinationen` auf Paare (Name, Urteil) REDUZIERT und dann „keine Abweichung" ueber
genau dieser selbstgewaehlten Sicht gemeldet. Die Substanz-Aussage haelt und ist unabhaengig
nachgerechnet — alle 19 Urteile identisch, `ok`, `ist_referenzmessung`, `bauhost_marke`, `grenze_s`,
`latte_aus_der_klammer` und alle Zaehlfelder unveraendert. Falsch war die REICHWEITE des Satzes,
nicht sein Kern. Ein Pruefer, der seine Vergleichsmenge selbst waehlt und das Ergebnis dann als
vollstaendig meldet, ist der Nachbar des Fundes darueber, nicht sein Gegenteil.

## S34 — Zwei einzeln korrekte Riegel schliessen zusammen die Tuer zur Signatur

Dies ist der Punkt, an dem 6.0.0 heute steht. Er gehoert hierher und nicht nur in den Bericht, weil
die Vorab-Quittung diese Datei bindet und ein Leser des Registers den Zustand ohne ein zweites
Dokument sehen koennen muss.

**Die Kette, Glied fuer Glied gemessen am 09.09.2026 gegen den Kopf
`ce0bad546beabcefcfa02e4986ff0284c715577b`.**

1. `scripts/sign_readiness_artifact.py --gate-zeile-aus-verdikt <datei>` liest `notes.gate_zeile`
   aus einem Verdikt und bricht ab, wenn das Feld fehlt — woertlich *"refusing to invent one"*
   (`gate_zeile_aus_verdikt`, Zeilen 193-208). Die Begruendung steht daneben und ist richtig: ein
   Erzeuger, der die Gate-Zeile selbst bauen koennte, waere wieder die Baumaschine, die ihre eigene
   Freigabe beglaubigt.
2. `scripts/audit_candidate_matrix.py::_gate_line_error` prueft dann sechs Pflichtfelder
   (`_GATE_LINE_FIELDS`: `gate_version`, `workflow_datei`, `workflow_sha256`, `modus`, `head`,
   `verdict`), verlangt `gate_zeile.head == candidate.commit`, und seit dem 07.09.2026
   (Owner-Anordnung `OA-638966a598`, Option A) muss `verdict` in
   `_GATE_VERDICTS_PASS = frozenset({"WITHSTANDS_DEEPGATE"})` liegen — eine Allowlist mit **genau
   einem** Wert, ausdruecklich fail-closed.
3. Im ganzen Verwaltungsbaum traegt **genau eine** Datei ein brauchbares `notes.gate_zeile` als
   Objekt: `office/governance/deepgate_600_lauf3/gate_result_600_lauf4b_FIX_FIRST.json`. Sie
   scheitert an **beiden** Bedingungen — ihr `head` ist `917edc695b280c6fa80e0ab2a76490ff0f30632e`,
   und ihr Lauf ging `FIX_FIRST` aus. Zwei weitere grep-Treffer waren Fehlalarme: dort steht das
   Wort nur in einem Linsen-Verzeichnispfad, nicht als Feld.
4. Die Belege des Zeugen tragen `notes` als reinen **String** ("Abschluss-Beleg, vom
   b7runner-Oracle ausgestellt..."), nie ein `gate_zeile`-Objekt. Nachgemessen am eigenen Lauf
   `office/governance/berkeley_gate/runs/ce0bad546beabcef_20260908T230552Z.json`.
5. Und der Zeuge **kann** ueber einen proofbundle-Commit kein `WITHSTANDS_DEEPGATE` ausstellen:
   Pre-Sweep, Klassen-Ledger und Linsenablage liegen im Verwaltungsrepo, nicht in diesem Baum.
   Gemessen im Beleg zu diesem Kopf: 0 Linsen gegen einen Boden von 3, drei Komponenten
   `env_blocked`, Verdikt `PARTIAL_GATE_NO_WITHSTANDS[v4/sc2/NORMAL-3L3I/strength=PARTIAL]`.

**Folge, nuechtern:** es gibt heute keinen Weg, eine gueltige Gate-Zeile fuer den Kandidatenkopf zu
erzeugen — weder aus dem Zeugen noch aus dem Bestand. Die drei Bereitschaftsartefakte sind damit
nicht signierbar, und C6.2, C6.3 und C8.2 bleiben aus einem STRUKTURELLEN Grund rot, nicht wegen
einer vergessenen Messung. Die Messungen selbst liegen vor und sind an diesen Kopf gebunden.

**Das ist kein Defekt des Tores, und der Unterschied ist wichtig.** Beide Riegel sind einzeln
richtig. Der erste verhindert, dass sich der Erzeuger seine eigene Gate-Zeile schreibt. Der zweite
verhindert, dass ein Lauf mit `FIX_FIRST` eine Zeile liefert, die die Pruefung besteht — laut dem
Kommentar an `_GATE_VERDICTS_PASS` war genau das vorher moeglich (**ungeprueft mit benannter
Quelle**: der Docstring; ich habe den frueheren Zustand nicht selbst nachgefahren). Der Befund ist
die KOMBINATION: zwei Riegel schliessen zusammen eine Tuer, die keiner von beiden allein zumachen
wollte.

**Was es NICHT ist.** Kein Signaturbypass, kein Weg fuer einen Angreifer, keine Aussage ueber den
ausgelieferten Code. Der Schaden ist, dass der Release-Weg an einer Stelle endet, an der die
Evidenz vollstaendig vorliegt und nur ihre Beglaubigung nicht ausstellbar ist.

**Owner-Gebiet, ausdruecklich nicht meines.** Zwei Wege stehen offen — die Gate-Mechanik fuer
Fremd-Repos erreichbar machen (Komponenten aus dem Werkzeugrepo lesen statt aus dem beurteilten
Baum), oder ausdruecklich entscheiden, was fuer 6.0.0 als Gate-Zeile gilt. Keinen davon darf der
Erzeuger sich selbst geben; die Zeile existiert genau dafuer. Registerschluessel
`SIGNIERWERKZEUG-VERLANGT-EINE-GATE-ZEILE-DIE-ES-NIRGENDS-GIBT-01`.

### S34, Korrektur vom 09.09.2026 — die un-Gegenlesung hat ein Glied dieser Kette widerlegt

Der Abschnitt oben schliesst: „es gibt heute keinen Weg, eine gueltige Gate-Zeile fuer den
Kandidatenkopf zu erzeugen — weder aus dem Zeugen noch aus dem Bestand." **Der zweite Halbsatz war
zu weit, und eine unabhaengige Gegenlesung hat es gefunden** (`qwen3.8:27b`, Rang 1 mit
Verdiktsrecht, `VERDIKT: REJECT`, Punkt V5: die Fokussierung auf zwei Skripte sei eine unbegruendete
Annahme der Vollstaendigkeit).

**Nachgemessen, und der Einwand traegt.** Ein Erzeuger EXISTIERT:
`scripts/b7_deepgate_gate_zeile.py` mit dem Unterbefehl `stempeln`, der die Felder ADDITIV unter
`notes.gate_zeile` eines Gate-JSON schreibt (Schema `b7n0de.gate_zeile.v1`, eigene Testdatei). Er
entstand aus Owner-Auftrag `QITEM-DEEPGATE-VERSIONIERUNG-GATE-ZEILE-EICHKOPF-01` vom 05.09. und
kennt den Pruefer dieser Bahn ausdruecklich.

**Wo er liegt, gemessen:** auf dem Zweig `feat/deepgate/ownergo-versionierung-gate-zeile-eichkopf`
(`964f88abe`, dirty 0), in einem Worktree — und **nicht** im HEAD des Verwaltungsrepos
(`git cat-file -e HEAD:scripts/b7_deepgate_gate_zeile.py` → kein gueltiger Objektname).

**Warum mein Fehler diese Klasse ist:** ich hatte nach `gate_zeile` in
`office/governance/**.json` gesucht — der Flaeche der ARTEFAKTE — und daraus auf die Abwesenheit
eines ERZEUGERS geschlossen. Zwei verschiedene Fragen, eine Suche. Dieselbe Form, die dieser
Abschnitt anderen vorhaelt.

**Was von S34 stehen bleibt, und es ist der eigentliche Halt.** Glied 5 ist unberuehrt: ueber einen
proofbundle-Commit kann der Zeuge kein `WITHSTANDS_DEEPGATE` ausstellen, weil Pre-Sweep,
Klassen-Ledger und Linsenablage im Verwaltungsrepo liegen (gemessen: 0 Linsen gegen Boden 3, drei
Komponenten `env_blocked`). Und `_GATE_VERDICTS_PASS` laesst genau diesen einen Wert zu. **Der
Blocker ist also nicht „keine Gate-Zeile erzeugbar", sondern „kein BESTEHENDES Verdikt ueber einen
proofbundle-Commit erzeugbar".** Das ist schmaler, schaerfer und aendert die Owner-Frage nicht: sie
lautet weiterhin, ob die Gate-Mechanik fuer Fremd-Repos erreichbar wird.

**Zwei weitere Punkte der Gegenlesung, angenommen ohne Nachmessung noetig.** Sie nannte „beide
Riegel sind einzeln richtig" eine Schoenung: die Allowlist mit genau einem Wert ist eine
Owner-Policy (`OA-638966a598`), keine logische Notwendigkeit — „wirkt wie vorgesehen" ist die
ehrlichere Formulierung als „ist richtig", und ob ein PARTIAL fuer Bereitschafts-Evidenz genuegt,
ist genau die offene Owner-Frage. Und sie nannte die Einordnung als „strukturell statt eigener
Fehler" Selbstentlastung; das trifft insoweit zu, als die Kombination frueher haette auffallen
koennen — die Policy selbst stammt vom 07.09. und lag nicht in meiner Hand.

**Ein Punkt der Gegenlesung trifft NICHT.** Sie hielt Glied 4 („die Belege des Zeugen tragen `notes`
als reinen String") fuer ebenso ungeprueft wie die markierte Stelle. Das ist gemessen: der eigene
Lauf `runs/ce0bad546beabcef_20260908T230552Z.json` wurde gelesen und meldet `notes-Typ: str`.

**Nachtrag zur Korrektur, gemessen: das Landen des Erzeugers loest den Halt NICHT.** Die Korrektur
oben laesst offen, ob `b7_deepgate_gate_zeile.py stempeln` den Blocker aufheben wuerde, sobald es im
Hauptbaum liegt. Gemessen an der Quelle: es KOPIERT das Verdikt woertlich aus dem Laufergebnis
(`z["verdict"] = roh`) und schreibt `None` plus `verdict_hinweis`, wenn das Ergebnis keins fuehrt —
es erfindet keins, aus derselben Begruendung wie `gate_zeile_aus_verdikt`.

Damit ist die Kette geschlossen und die Aussage praezise: ein Stempel auf den Lauf ueber den
Kandidatenkopf ergaebe `verdict: PARTIAL_GATE_NO_WITHSTANDS[...]`, und `_GATE_VERDICTS_PASS` laesst
nur `WITHSTANDS_DEEPGATE` zu. **Der Erzeuger zu landen waere also kein Weg um den Halt herum.** Wer
das versucht, verliert einen Bau- und Pruefzyklus an einer Stelle, die nachweislich nichts aendert.

Die Owner-Frage bleibt damit unveraendert und ist die einzige: die Gate-Mechanik fuer Fremd-Repos
erreichbar machen, oder ausdruecklich entscheiden, welches Verdikt fuer eine Bereitschafts-Evidenz
genuegt.

### S30 (4), Nachtrag vom 09.09.2026 — die vierte Modulform verhaelt sich im sdist genauso, und das entscheidet ueber den Meta-Test

Der Nachtrag (4) oben mass den Zip-Import im CHECKOUT: `importlib.util.find_spec` findet das Modul
im Archiv, `_fehlende_datei_aus` meldet es trotzdem als fehlend. Der Entwurf des fehlenden
Meta-Tests nannte seine eigene offene Vorbedingung woertlich: ungemessen sei, „ob der Fall im
extrahierten sdist dieselbe Antwort gibt wie im Checkout".

**Jetzt gemessen, im wirklich gebauten und extrahierten sdist** (`proofbundle-6.0.0.tar.gz`,
2 204 279 Bytes, gebaut am Kopf `ce0bad5`): der sdist traegt `_fehlende_datei_aus`,
`zip_import_moeglich` ist `True`, und der Riegel meldet `scripts/gepacktes_modul.py` als fehlend —
**identisch zum Checkout**. Die Luecke ist also keine Eigenschaft der Entwicklungsumgebung, sondern
der Formenliste selbst, und sie reist mit der Auslieferung.

**Warum daraus TROTZDEM kein Test in dieser Runde wird, und der Grund ist ein anderer als vorher.**
Bisher stand hier „die Form hat keinen Gegenstand im Baum". Das war die Begruendung gegen einen
RIEGEL und ist gegen einen META-TEST kein Argument — der baut sich sein Archiv selbst und braucht
keins im Baum. Die Verwechslung ist hiermit benannt. Was gegen den Test in DIESER Runde spricht,
ist seine Bauart: ein Fall, der behauptet „der Riegel MELDET faelschlich", friert einen Defekt ein
und wuerde rot, sobald jemand die Formenliste korrekt erweitert. Ein Fall, der die EIGENSCHAFT
prueft („ein aus irgendeiner Quelle importierbares Modul darf nicht als fehlend gelten"), waere
heute rot. Beides ist in einer Release-Linie unter der Owner-Regel „Fix nur bei P0" falsch
platziert.

**Was der Messwert wert ist, auch ohne Test:** die Klasse
`aufzaehlung_statt_existenzfrage_bindet_nur_die_listeneintraege` bleibt im Klassen-Ledger des deep
gate zu Recht `class_open`, und sie bleibt es jetzt mit einer Messung in BEIDEN Umgebungen statt
nur im Checkout. Wer sie nach dem Tag schliesst, hat die Vorbedingung nicht mehr zu klaeren.

## S35 — Meine Owner-Frage stand auf einer zu schmalen Messung: es sind drei Waende, nicht eine

> ⚠ **ZWEIMAL KORRIGIERT — die gueltige Fassung steht in S49.** Dieser Abschnitt nennt „Wand 2"
> Owner-Gebiet mit der Begruendung, der Zeuge fuehre kein Verdikt. **Die Begruendung ist falsch**
> (416 von 418 Belegen tragen `verdict_tag`), **der Schluss ist richtig**: Wand 2 bleibt eine
> Festlegung, weil der Zeuge nicht der Erzeuger der Gate-Zeile ist — das ist das Workflow-Verdikt,
> und dessen Wertform ist mit dem Pruefer deckungsgleich. S42 zog daraus den Gegenschluss („nur
> Wand 3 ist Owner-Gebiet"); **S42 ist von einer Opus-Linse widerlegt und von mir nachgemessen.**
> Der Abschnitt bleibt unveraendert, weil er die Messungen traegt, die weiterhin gelten.

(Korrigiert S34 und dessen erste Korrektur. Beide bleiben stehen — was sie messen, stimmt; was sie
daraus schliessen, war zu weit.)

S34 und seine erste Korrektur enden beide mit derselben Frage an den Owner: *„die Gate-Mechanik
fuer Fremd-Repos erreichbar machen, oder ausdruecklich entscheiden, welches Verdikt genuegt."*
**Diese Frage setzt voraus, dass das Fremd-Repo die Wand ist. Nachgemessen ist sie die dritte von
drei, und die ersten beiden stehen genauso im Verwaltungsrepo selbst.**

Der Fehler ist derselbe, den dieses Register schon zweimal gegen mich fuehrt: ich habe die
proofbundle-Seite gemessen und ueber den Mechanismus geurteilt. Die Frage „funktioniert das
ZUHAUSE, wo alle Teile liegen?" habe ich nie gestellt.

**Messung 1 — der Bestand, erschoepfend statt stichprobenartig.** 337 771 JSON-Dateien unter
`~/2bedone`, `~/proofbundle` und dem Arbeitsbaum gelesen und auf ein `notes.gate_zeile` als Objekt
geprueft. **Vier Treffer, und es ist VIER MAL DIESELBE DATEI** (`gate_result_600_lauf4b_FIX_FIRST.json`,
einmal im Hauptbaum, dreimal in Worktrees). Ihre Zeile fuehrt 21 Felder, und `verdict` ist keines
davon — sie faellt also schon an der Feldpruefung, nicht erst am Kopf-Vergleich.

**Messung 2 — die Belege des Zeugen, alle.** `office/governance/berkeley_gate/runs/` fuehrt **412
Belege, davon 145 mit `strength: FULL`**, die sechs juengsten aus dem Abend und der Nacht 08./09.09. (bis 00:11Z).
**Null von 412 tragen `notes` als Objekt.** Alle tragen es als Zeichenkette („Abschluss-Beleg, vom
b7runner-Oracle ausgestellt…"), und `verdict` ist auf allen `None`. Der Zeuge ist kein Erzeuger von
Gate-Zeilen — auch nicht bei voller Staerke, auch nicht ueber einen Kopf des eigenen Repos.

**Messung 3 — und das ist der eigentliche Fund. Der Erzeuger und der Pruefer benennen dieselben
Dinge verschieden.** Ich habe den FULL-Beleg von heute Nacht (`acd65a65…`) in den bestehenden
Erzeuger `b7_deepgate_gate_zeile.messen()` gegeben und die entstandene Zeile Feld fuer Feld gegen
`_GATE_LINE_FIELDS` gehalten — ausgefuehrt, nicht aus dem Quelltext geschlossen:

| Pruefer (proofbundle) verlangt | Erzeuger (Verwaltungsrepo) liefert | Ergebnis |
|---|---|---|
| `gate_version` | `gate_version` | OK (`"v4"`) |
| `workflow_datei` | `workflow_path` | **fehlt** |
| `workflow_sha256` | `workflow_digest` | **fehlt** |
| `modus` | `modus` | OK (`"NORMAL 3L/3I"`) |
| `head` (40 hex) | `verdikt_head`, und nur wenn das Laufergebnis `head` fuehrt | **fehlt** |
| `verdict` | `verdict`, woertlich kopiert | **`None`** |

**Vier von sechs Pflichtfeldern fehlen, drei davon aus reiner Namensdrift.** `workflow_lage()`
schreibt `workflow_path`/`workflow_digest` (Zeilen 128-140), `messen()` schreibt `verdikt_head`
(Zeile 227-228) — der Pruefer verlangt `workflow_datei`, `workflow_sha256`, `head`. Das sechste
Feld ist leer, weil der Zeugenbeleg den Kopf `digest` nennt und `verdict` gar nicht fuehrt.

**Wer hier von wem abgewichen ist, laesst sich datieren.** Die eine handgebaute Datei folgt der
Benennung des Pruefers exakt (`gate_version`, `head`, `modus`, `workflow_datei`, `workflow_sha256`
— fuenf von sechs; das sechste, `verdict`, kam am 07.09. per `OA-638966a598` beim Pruefer dazu).
Das WERKZEUG entstand am 05.09. aus `QITEM-DEEPGATE-VERSIONIERUNG-GATE-ZEILE-EICHKOPF-01` und
waehlte eigene Namen. Zwei Bahnen, ein Vertrag, zwei getippte Listen, kein gemeinsamer Ort und kein
Test, der eine gegen die andere faehrt.

**Die drei Waende, getrennt und einzeln bepreist.**

1. **Namensdrift (Verwaltungsrepo, nicht dieser Baum).** Drei Feldnamen. Ein Test, der eine erzeugte
   Zeile gegen die Pflichtliste des Pruefers faehrt, haette das am Bautag gefangen. Verletzte
   Invariante: **ein Vertrag zwischen zwei Bahnen als zwei getippte Aufzaehlungen** — dieselbe
   Klasse, die dieses Register am 08.09. als Ledger-Nr. 295 aufgenommen hat
   (`aufzaehlung_statt_existenzfrage_bindet_nur_die_listeneintraege`) und die
   `B7_STANDING_SCHEMA_SSOT` adressiert.
2. **Der Zeuge fuehrt kein Verdikt.** Er fuehrt `strength: FULL|PARTIAL` und `digest`, nie `verdict`
   und nie `head`. Selbst nach Wand 1 traegt eine gestempelte Zeile `verdict: None`, und
   `_GATE_VERDICTS_PASS` haelt an. Das ist kein Versehen: der Stempel KOPIERT und erfindet nichts,
   aus derselben Begruendung wie `gate_zeile_aus_verdikt`. Es fehlt eine Abbildung von `strength`
   auf ein Verdikt — und die ist eine Festlegung, keine Messung.
3. **Fremd-Repo.** Erst hier greift, was S34 als einzige Wand beschrieb. Ueber
   `60bb6d935df15558…` (zwei Laeufe, beide PARTIAL) nennt der Beleg die Ursache woertlich, viermal
   dieselbe Form: `scripts/b7_berkeley_pre_sweep.py fehlt im content-adressierten Baum`,
   `office/governance/berkeley_gate/class_ledger.jsonl fehlt im content-adressierten Baum`
   (zweimal, fuer Ledger-Replay und Anti-Tautologie-Probe), und `0 nicht-leere Linsen-Artefakte`
   gegen einen Boden von 3. Die Pfade sind feste Konstanten im Zeugen (`_PRE_SWEEP_REL`,
   `_LEDGER_REL`, `_LENS_ROOT_REL`), und dass sie aus dem BEURTEILTEN Baum gelesen werden, ist die
   Eigenschaft, die den Beleg faelschungsfest macht — nicht ihr Defekt. Zum Vergleich: **145 von
   145 FULL-Belegen zaehlen drei oder mehr Linsen**, die vier von heute Nacht je acht.

**Was das an der Owner-Frage aendert.** Sie war zu eng und in der bequemen Richtung falsch: sie
schob den Halt vollstaendig auf eine Eigenschaft des fremden Repos und damit weg von der Mechanik,
die in beiden Bahnen gebaut wurde. Richtig gestellt:

> Wand 1 ist eine Namensangleichung im Verwaltungsrepo und braucht keine Owner-Entscheidung, nur
> einen Zug in der anderen Bahn — mit einem Test, der die erzeugte Zeile gegen die Pflichtliste
> faehrt, sonst driftet sie wieder. **Wand 2 und Wand 3 sind Owner-Gebiet:** ob ein `strength: FULL`
> des Zeugen als `WITHSTANDS_DEEPGATE` gelten darf (Wand 2), und ob ein Beleg ueber einen
> proofbundle-Commit ueberhaupt FULL erreichen koennen soll, wenn die Pruefmechanik dafuer aus einem
> ANDEREN Baum gelesen werden muesste als dem beurteilten (Wand 3) — was genau die Eigenschaft
> aufgibt, die den Beleg heute traegt.

**Ehrliche Grenzen dieser Messung.** Ich habe `messen()` mit einem Zeugenbeleg als `gate_json`
gefahren; das ist die Form, die hier gebraucht wuerde, aber nicht nachweislich die, fuer die das
Werkzeug gedacht war — es kennt auch Gate-JSONs des Workflows, und ueber DIE habe ich nichts
gemessen. `workflow_datei`/`workflow_sha256` koennten in einem Workflow-Gate-JSON anders entstehen.
Was davon unberuehrt bleibt: `head` und `verdict` kommen in beiden Faellen aus dem Laufergebnis, und
der Zeugenbeleg fuehrt beide nicht. Registerschluessel
`ERZEUGER-UND-PRUEFER-DER-GATE-ZEILE-BENENNEN-DREI-FELDER-VERSCHIEDEN-01`.

### S35, Nachtrag vom 09.09.2026 — die Gegenlesung hat vier Stellen getroffen, drei davon tragen

Fremdfamiliaere Gegenlesung von S35/S36 (`qwen3.8:27b`, `VERDIKT: ACCEPT` mit fuenf Punkten). Ein
ACCEPT ist hier kein Freibrief: vier der fuenf Punkte benennen echte Luecken, und einer davon ist
schwerer als alles, was S35 selbst gefunden hat.

**Punkt 1, angenommen und NACHGEMESSEN.** Die Feld-fuer-Feld-Tabelle lief an EINEM Beleg; der Satz
„der Zeuge fuehrt nie `head`" galt darueber hinaus nicht. Jetzt ueber alle gemessen:
**0 von 412 Belegen tragen ein nicht-leeres `head`; 410 von 412 tragen `digest`.** Genau EIN Beleg
fuehrt ein nicht-leeres `verdict`, und er ist kein Abschluss-Beleg, sondern eine Fund-Aufzeichnung
(`af79b988ac8726e9_20260722_FULL_DEEP_findings.json`, `record_type`, Feld
`not_a_withstands_receipt`, `verdict: DOES_NOT_WITHSTAND`, `strength: NOT_COMPUTED_FINDINGS_OPEN`).
Der zweite Beleg ohne `digest` ist ein `.components.json`-Beiwerk. Die Aussage haelt also fuer die
Beleg-Familie — aber sie hielt sie vorher aus einer Stichprobe von eins, und das war der Fehler.

**Punkt 2, angenommen.** „Drei davon aus reiner Namensdrift" stimmt fuer zwei. Bei `head` steht die
Bedingung in derselben Tabelle zwei Zeilen darueber (`und nur wenn das Laufergebnis head fuehrt`) —
das Feld ist anders benannt UND bedingt. Richtig: **zwei aus reiner Namensdrift, das dritte
zusaetzlich bedingt, und die Bedingung ist nach Punkt 1 in 412 von 412 Faellen nicht erfuellt.**

**Punkt 3 — und das ist der schwerste Fund dieses Abschnitts, gegen mich.** S35 benennt die Klasse
(*„ein Vertrag als zwei getippte Aufzaehlungen, ohne gemeinsame Quelle und ohne Test"*) und schlaegt
im selben Atemzug einen Fix vor, **der die Klasse neu erzeugt**: ein Test, der „die erzeugte Zeile
gegen die Pflichtliste faehrt", muss diese Liste irgendwo hernehmen — hartkodiert waere sie die
DRITTE getippte Aufzaehlung, importiert waere sie eine Abhaengigkeit der Werkstatt vom Produkt.

Damit ist Wand 1 auch nicht mehr das, was S35 aus ihr gemacht hat („keine Entscheidung, nur ein
Zug"). Zwei Festlegungen stecken darin, und beide gehoeren benannt:

* **Welche Seite gibt die Namen vor?** Das Indiz zeigt in eine Richtung — die eine handgebaute Datei
  im Bestand folgt dem Pruefer in fuenf von sechs Feldern, und das Werkzeug ist der juengere
  Abweichler —, aber ein Indiz ist keine Entscheidung.
* **Wo wohnt der Vertrag, damit er EINE Quelle hat?** Die Form, die die Klasse wirklich schliesst,
  restated die Liste nicht, sondern **fuehrt den Pruefer aus**: der Test in der anderen Bahn laesst
  die erzeugte Zeile durch `_gate_line_error` des ausgelieferten proofbundle-Pakets laufen. Dann gibt
  es genau eine Autoritaet, und der Test kann von ihr nicht abdriften, weil er sie benutzt. Das ist
  keine neue Abhaengigkeit: das Verwaltungsrepo verifiziert Zeugen-Belege bereits gegen ein
  installiertes `proofbundle`.

**Punkt 4, angenommen.** S35 nennt nicht, WO `messen()` ausgefuehrt wurde. Nachgetragen: im Worktree
`.claude/worktrees/deepgate-version` (Zweig
`feat/deepgate/ownergo-versionierung-gate-zeile-eichkopf`), also in genau dem Baum, in dem das
Werkzeug ueberhaupt existiert — es liegt nicht im HEAD des Verwaltungsrepos. Die zitierten
Zeilennummern (128-140, 227-228) gehoeren zu dieser Fassung.

**Punkt 5 traf nicht** und wurde von der Gegenlesung selbst so entschieden: der Widerspruch zu S34
ist in S35 ausdruecklich benannt.

**Was das an der Owner-Frage aendert.** Wand 1 bleibt kein Owner-Gate im Sinne von „Tuer auf/zu",
aber sie ist auch kein reiner Handgriff: sie traegt eine Architekturfestlegung (wo wohnt der
Vertrag). Sie gehoert als solche in die andere Bahn uebergeben, nicht als Rename-Auftrag.

### S35, zweiter Nachtrag — meine eigene Empfehlung war so nicht ausfuehrbar

Der Nachtrag oben empfiehlt als Klassen-Fix, der Test in der anderen Bahn solle die erzeugte Zeile
**„durch `_gate_line_error` des ausgelieferten proofbundle-Pakets laufen"** lassen. **Nachgemessen
geht das so nicht.**

```
find . -name audit_candidate_matrix.py   ->  ./scripts/audit_candidate_matrix.py   (nur dort)
pyproject.toml  [tool.setuptools.packages.find]  where = ["src"]
venv: importlib.util.find_spec("audit_candidate_matrix")  ->  None
```

**Der Pruefer ist kein Teil des ausgelieferten Pakets.** Er liegt in `scripts/`, und gepackt wird
ausschliesslich `src/proofbundle`. Ein `import` aus einer Installation kann ihn nicht erreichen.

**Was bleibt und was sich aendert.** Die RICHTUNG stimmt weiter — ein Test, der den Pruefer
AUSFUEHRT, kann nicht von ihm abdriften; einer, der die Liste abschreibt, schon. Nur der Weg dahin
ist ein anderer, und es sind zwei:

* **Heute moeglich:** die andere Bahn laedt `scripts/audit_candidate_matrix.py` per Pfad aus einem
  proofbundle-CHECKOUT. Den hat sie ohnehin — der Zeuge zieht seine Objekte aus
  `/home/konrad/proofbundle`, und die Repo-Zuordnung dort nennt genau diesen Pfad. Das ist keine
  neue Abhaengigkeit, aber es bindet an einen Arbeitsbaum statt an eine Version.
* **Sauber, und es ist MEINE Bahn, nach dem Tag:** der Vertrag (die sechs Feldnamen plus die
  Verdikt-Allowlist) wandert nach `src/proofbundle/`, wird damit ausgeliefert und ist versioniert
  zitierbar. Dann bindet der Test an eine VERSION statt an einen Baum. Das ist kein P0 und gehoert
  unter der Owner-Regel nicht in diese Release-Linie — aber es ist der Schritt, der die Klasse auf
  meiner Seite wirklich schliesst, und er gehoert auf die Liste fuer danach.

**Warum dieser Nachtrag ueberhaupt noetig war, und das ist die eigentliche Lehre.** Ich habe eine
Empfehlung ausgesprochen, ohne zu pruefen, ob sie ausfuehrbar ist — im selben Abschnitt, in dem ich
mir von einer Gegenlesung habe zeigen lassen, dass mein vorheriger Vorschlag die eben benannte
Klasse neu erzeugt. **Zwei Vorschlaege hintereinander, beide ungeprueft, beide in einem Text, der
Pruefdisziplin einfordert.** Ein Vorschlag ist eine Behauptung ueber die Zukunft und wird gemessen
wie jede andere: existiert das, was er benutzt?

## S36 — Der Pre-Sweep des Tores reisst sein eigenes Zeitlimit, und der Zustand dafuer heisst „Umgebung"

Nebenbefund derselben Runde, gemessen am 09.09.2026 im echten Verwaltungs-Checkout (also mit
vollstaendig vorhandener Mechanik, nicht im Wegwerfbaum):

```
status: env_blocked · roh_ergebnis: env · trackung_lage: gemessen
detail: pytest riss das Zeitlimit von 240s ueber 190 Knoten (ausfuehrbar, aber zu langsam)
n_classes_total: 200 · n_classes_replayed: 98 · replayed_class_coverage: 0.49
n_class_closed_fields_unusable: 0 · MESSFELD: GETEILT (Last 5,59 auf 24 Kernen)
```

**Zwei Dinge daran gehen ueber diesen Lauf hinaus.**

Erstens: der Ledger waechst monoton — das ist sein Zweck —, das Zeitbudget von 240 s ist fest. 190
Knoten passen nicht mehr hinein. Das Gedaechtnis des Tores waechst aus der Zeit heraus, die es
erinnern darf, und der Ausgang davon ist ein blockierender Zustand. Kein Defekt, eine Bauart.

Zweitens, und das ist die Klasse: `_RES_TO_STATUS` bildet `env` auf `env_blocked` ab, und
`env_blocked` heisst laut seinem eigenen Modul *„die Messstation hat die deklarierte Umgebung
nicht"*. Hier fehlt der Station nichts — sie ist zu langsam. Der Text muss seinem eigenen
Zustandswort widersprechen (*„NICHT die Umgebung"*), damit der Leser es richtig liest, und der
Verbraucher im Beleg (`_measured_replay_problems`) liest nur `status`. **Zwei verschiedene Ursachen
teilen ein Wort; im Beleg sind sie nicht mehr unterscheidbar.** Das ist derselbe Gedanke, den
`riegel_haben_drei_zustaende.md` gegen die Verwechslung von `error` und `env_blocked` schon einmal
durchgesetzt hat — hier fehlt die vierte Unterscheidung.

**Nicht meine Bahn:** beides liegt im Verwaltungsrepo. Aufgeschrieben, damit es nicht verloren geht,
und weitergegeben statt gefixt. Registerschluessel `PRESWEEP-ZEITLIMIT-HEISST-UMGEBUNG-FEHLT-01`.

## S37 — Die Korrektur in EINEM Zug: die drei Waende sind eine UND-Kette, und ich habe den dritten Weg nie angeboten

> ⚠ **ZWEIMAL KORRIGIERT — die gueltige Fassung steht in S49.** Dieser Abschnitt nennt „Wand 2"
> Owner-Gebiet mit der Begruendung, der Zeuge fuehre kein Verdikt. **Die Begruendung ist falsch**
> (416 von 418 Belegen tragen `verdict_tag`), **der Schluss ist richtig**: Wand 2 bleibt eine
> Festlegung, weil der Zeuge nicht der Erzeuger der Gate-Zeile ist — das ist das Workflow-Verdikt,
> und dessen Wertform ist mit dem Pruefer deckungsgleich. S42 zog daraus den Gegenschluss („nur
> Wand 3 ist Owner-Gebiet"); **S42 ist von einer Opus-Linse widerlegt und von mir nachgemessen.**
> Der Abschnitt bleibt unveraendert, weil er die Messungen traegt, die weiterhin gelten.

Dies ist bewusst KEIN vierter Nachtrag. Eine Gegenlesung hat genau das beanstandet: in S34/S35
stehen vier Korrekturrunden hintereinander, und eine so dichte Folge Behauptung → Widerlegung →
naechste Behauptung senkt das Vertrauen in die jeweils STEHENDE Aussage, statt Reife zu belegen.
Der Einwand trifft. Also einmal richtig, statt ein fuenftes Mal knapp daneben.

**Was aus S35 unveraendert stehen bleibt: die MESSUNGEN.** Eine unabhaengige Gegenlesung hat sie
Zahl fuer Zahl selbst nachgefahren und bestaetigt: 412 Belege, 145 FULL, 0 mit `notes` als Objekt,
410 mit `digest`, **0 mit nicht-leerem `head`**, genau 1 mit einem `verdict` (und der ist eine
Fund-Aufzeichnung mit `not_a_withstands_receipt: true`, kein Abschluss-Beleg), 145 von 145 FULL mit
mindestens drei Linsen, die Feldnamen-Tabelle exakt, `find_spec("audit_candidate_matrix") is None`.

**Was falsch war, ist die STRUKTUR der Schlussfolgerung.**

### Die drei Waende sind kein Menue, sondern eine UND-Kette

S35 schrieb „Die drei Waende, getrennt und einzeln bepreist" — das liest sich wie drei Baustellen,
von denen man eine anfassen kann. Der eigene Text widerlegt es zwei Absaetze weiter: *„Selbst nach
Wand 1 traegt eine gestempelte Zeile `verdict: None`."*

Richtig ist:

* **Wand 1 allein zu schliessen aendert am Ergebnis NICHTS** — die Zeile traegt danach die richtigen
  Feldnamen und immer noch kein Verdikt.
* **Wand 1 und 2 zusammen aendern am Ergebnis NICHTS**, solange der Gegenstand ein
  proofbundle-Commit ist: der Beleg bleibt strukturell `PARTIAL` (drei Komponenten `env_blocked`,
  0 Linsen gegen Boden 3).
* Erst **alle drei** oeffnen die Tuer. Es sind drei notwendige Bedingungen fuer DIESELBE Tuer, nicht
  drei Tueren.

„Einzeln bepreist" war die bequeme Lesart. „Gemeinsam scharf" ist die richtige, und sie aendert die
Entscheidungslage: eine einzelne Ja-Antwort kauft nichts.

### Und damit der Punkt, den ich dem Owner schuldig geblieben bin: was passiert bei NEIN?

Die zwei Zeilen in S35 nannten nur die Folge von JA. Vollstaendig:

| Weg | Was zu tun ist | Folge |
|---|---|---|
| **A — alle drei Waende** | Namen angleichen (andere Bahn) · Abbildung `strength: FULL` → `WITHSTANDS_DEEPGATE` festlegen · die Pruefmechanik aus einem anderen Baum lesen lassen als dem beurteilten | die Bereitschaftsartefakte werden signierbar. Preis: Wand 3 gibt genau die Eigenschaft auf, die den Beleg heute faelschungsfest macht |
| **B — den Pruefer aendern** | `_GATE_VERDICTS_PASS` um ein Verdikt erweitern, das ein ehrliches PARTIAL traegt | schneller, aber **widerruft eine per Test gebundene Festlegung**: `tests/test_freigabe_evidenz_provenienz_l5_g7_02.py` bindet `WITHSTANDS_DEEPGATE_PARTIALLY` ausdruecklich als ABLEHNUNG. Und es ist eine Aenderung an der Zulassung JEDER freigabeentscheidenden Pruefung |
| **C — gar nichts** | die vier Bereitschaftsartefakte bleiben UNSIGNIERT; ihre Messungen liegen vor und reisen als benanntes Restrisiko mit | verlangt keinen Bau und keinen Widerruf. **Dass er den Tag nicht aufhaelt, ist NICHT GEMESSEN, sondern meine Folgerung aus einem Praezedenzfall:** der Owner hat fuer C6.3 (24h-Soak) woertlich so entschieden („bleibt benanntes Restrisiko und haelt den Tag nicht"). Ob dasselbe fuer die uebrigen drei Artefakte gilt, hat er NICHT gesagt und kann nur er sagen |

**Weg C habe ich in keinem der bisherigen Blaetter angeboten, und das war die eigentliche
Auslassung.** Er ist der einzige Weg, der ohne Bau, ohne Widerruf und ohne Eigenschaftsverlust
auskommt. **Ehrliche Grenze, und sie gehoert in denselben Satz:** dass er den Tag nicht aufhaelt,
ist eine FOLGERUNG aus einem einzigen Praezedenzfall (C6.3), nicht eine Messung — die uebrigen drei
Artefakte hat der Owner nie so eingeordnet, und ein Praezedenzfall ist keine Regel. Meine Aufgabe
war, den Weg ueberhaupt zu nennen; seine Reichweite bestimmt er.

### Vier weitere Einwaende, angenommen

**Die vier Dateien mit einer Gate-Zeile sind NICHT byte-gleich.** Gegengemessen: nur die drei
Worktree-Kopien sind identisch; die Kopie im Hauptbaum traegt ein Feld mehr
(`presweep_kanonisch_pin_art`, am 08.09. nachgetragen) und hat damit **21 Felder, die anderen drei
20**. Mein „ihre Zeile fuehrt 21 Felder" galt fuer eine von vieren. Die tragende Aussage — `verdict`
fehlt — ist in allen vier Fassungen nachgemessen wahr.

**Mein Ersatzweg verletzt einen eigenen Anker.** S35 bot an, den Pruefer „per Pfad aus einem
proofbundle-CHECKOUT" zu laden, und nannte als Nachteil nur „bindet an einen Arbeitsbaum statt an
eine Version". Der schwerere Nachteil fehlte: ein Pruefer aus einem mutierbaren, ungepinnten
Checkout ist genau das, was `B7_STANDING_DETERMINISTIC_VERIFIER` ausschliessen soll — und er ist
selbst das Freigabe-Tor. Damit bleibt von den zwei angebotenen Wegen nur der zweite: den Vertrag
nach `src/proofbundle/` verlegen, ausliefern, versioniert zitieren. Meine Bahn, nach dem Tag.

**Ein Widerspruch zu S34 stand unbenannt.** S34 schrieb „kein Defekt des Tores. Beide Riegel sind
einzeln richtig." Wand 1 ist ein echter Koordinationsfehler zwischen Erzeuger und Pruefer, und ich
habe ihn selbst als Klassendefekt gebucht. Eine verletzte Vertragsinvariante IST ein Defekt. Der
Satz aus S34 gilt nur noch fuer das Zusammenspiel der beiden Riegel, nicht fuer die Mechanik als
Ganzes; hiermit benannt statt stehen gelassen.

**Die Grenze von „erschoepfend".** Die Durchsuchung lief mit `os.walk` ueber `/home/konrad/2bedone`,
`/home/konrad/proofbundle` und `/mnt/bigstore/claude_scratch/pb_pushlinie`, ohne `.git`,
`node_modules`, `__pycache__`, `.venv`, `venv`, `.mypy_cache`, `.pytest_cache`, und ohne Dateien
ueber 8 MB. Worktrees UNTERHALB dieser Wurzeln waren eingeschlossen (drei der vier Treffer liegen
in `.claude/worktrees/`), Worktrees ausserhalb nicht. Das ist die Menge, ueber die „vier Treffer"
gilt — nicht „das ganze System".

### Wie man die zwei Kernzahlen selbst nachfaehrt

```
# 412 Belege / 145 FULL / notes-Typ / head / digest
python3 - <<'P'
import json, glob
b=[json.load(open(p)) for p in glob.glob(
   "office/governance/berkeley_gate/runs/*.json")]
print(len(b), sum(1 for j in b if j.get("strength")=="FULL"),
      sum(1 for j in b if isinstance(j.get("notes"), dict)),
      sum(1 for j in b if str(j.get("head") or "").strip()),
      sum(1 for j in b if str(j.get("digest") or "").strip()))
P
# die Feldtabelle: Erzeuger auf einen echten Beleg anwenden und gegen den Pruefer halten
#   messen() aus .claude/worktrees/deepgate-version/scripts/b7_deepgate_gate_zeile.py
#   gegen _GATE_LINE_FIELDS aus proofbundle scripts/audit_candidate_matrix.py:298
```

**Und die Lehre der Gegenlesung, die keine Zahl betrifft:** vier Korrekturrunden an EINEM Befund in
einer Nacht sind selbst ein Messwert. Sie sagen, dass der Befund zu frueh geschrieben wurde — nicht,
dass der Autor gruendlich ist. Registerschluessel `DREI-WAENDE-SIND-EINE-UND-KETTE-KEIN-MENUE-01`.

### S36 nachgemessen — und die Messung entscheidet die Frage NICHT, die sie entscheiden sollte

Eine Gegenlesung hielt S36 vor, dass die Messfeld-Zeile (`GETEILT`, Last 5,59) zwar im Register
steht, aber im Blatt fehlte — der Zeitlimit-Fund erschien dort als reine Bauart, obwohl die Maschine
unter fremder Teillast lief. Der Einwand trifft, und ich habe nachgemessen.

**Die 190 Knoten einzeln gefahren, mit `--durations=0`, ohne das Zeitlimit des Sweeps:**

```
Wanduhr 290 s · pytest meldet 272,96 s · 194 passed, 2 skipped, RC=0
Summe nur der call-Phasen: 251,3 s ueber 75 Tests (496 weitere unter 5 ms)
MESSFELD vorher GETEILT (Last 5,35) · nachher GETEILT (Last 10,02) auf 24 Kernen
```

**Was das zeigt und was NICHT.** Die reine Testarbeit allein (251,3 s) liegt schon ueber dem Budget
von 240 s, bevor Sammlung, Auf- und Abbau dazukommen. **Aber `--durations` misst unter derselben
Last** — ein Test, der verdraengt wird, meldet selbst eine laengere Dauer. Der Abstand betraegt
4,6 %, und das ist genau die Groessenordnung, die Verdraengung bei Last 5 bis 10 erklaeren kann.
**Diese Messung entscheidet also NICHT, ob das Zeitlimit auf einer ruhigen Maschine halten wuerde.**
Eine ruhige Maschine ist hier nicht herstellbar: der 24h-Soak des Owners laeuft und soll laufen.

**Was unabhaengig von der Last stehen bleibt, und das ist der eigentliche Punkt:** der Klassen-Ledger
waechst monoton — er ist ein Gedaechtnis, das ist sein Zweck —, und das Budget ist eine feste Zahl.
Zwischen der Messung von gestern Nacht (200 Klassen) und heute (201) ist er wieder gewachsen. Ob
der heutige Lauf durch Last oder durch Umfang ueber die Linie ging, aendert nichts daran, dass die
Reserve aufgebraucht ist. Der Fund ist damit belastbar als **Trend**, nicht als Einzelurteil — und
so gehoert er formuliert, in beiden Dokumenten.

**Der zweite Teil von S36 ist von der Last voellig unberuehrt** und wurde von einer Gegenlesung an
der Quelle bestaetigt: `scripts/b7_berkeley_class_ledger.py:182` gibt bei `TimeoutExpired` den Wert
`"env"` zurueck, mit einem Text, der woertlich sagt *„NICHT die Umgebung"*;
`b7_berkeley_pre_sweep.py:35` bildet `"env"` auf `env_blocked` ab; und
`b7_berkeley_gate_receipt._measured_replay_problems` liest nur `status`. **Zwei verschiedene
Ursachen — Station unvollstaendig, Station zu langsam — teilen ein Wort, und im signierten Beleg
sind sie nicht mehr unterscheidbar.** Das ist ein Befund ueber die Mechanik, keine Aussage ueber
eine Maschine, und er haengt an keiner Lastmessung.

### Der Beleg zu diesem Abschnitt ist an Wand 3 gescheitert — an genau dem Mechanismus, den er beschreibt

Nach dem Schreiben von S37 habe ich fuer seine Kernaussage einen Abschluss-Beleg beim Zeugen geholt,
korrekt gebunden (`--repo /home/konrad/proofbundle`, volle SHA `9906d91439e2ef5a…`). Vorher lagen
drei Gegenlesungen als Linsen-Artefakte bereit, **committet** im Verwaltungsrepo (`71be4f2e5`), zwei
Familien, Panel-Boden erreicht — `b7_linsen_ablage.py lage` meldete `reicht: true`.

Der Zeuge zaehlte **null**:

```
strength: PARTIAL
  deterministic_pre_sweep : scripts/b7_berkeley_pre_sweep.py fehlt im content-adressierten Baum
  class_ledger_replay     : .../class_ledger.jsonl fehlt im content-adressierten Baum
  anti_tautology_meta_test: .../class_ledger.jsonl fehlt im content-adressierten Baum
  jury                    : 0 nicht-leere Linsen-Artefakte gezaehlt, Boden 3
```

Und das Werkzeug sagte den Grund vorher, woertlich: *„das Verzeichnis existiert im Baum von
9906d91439e2 nicht — null committete Linsen-Artefakte."* Die Linsen liegen im Verwaltungsrepo, der
beurteilte Baum ist ein proofbundle-Commit, und der Zeuge liest **aus dem beurteilten Baum**.

**Damit ist Wand 3 nicht mehr nur beschrieben, sondern vorgefuehrt** — an dem Beleg, der sie
beschreibt. Der Zusammenhang ist kein Argument mehr, sondern ein Lauf: dieselbe Mechanik, die den
vier Bereitschaftsartefakten die Signatur verweigert, verweigert auch dem Registereintrag ueber sie
sein FULL. Der Beleg bleibt ehrlich `PARTIAL`
(`office/governance/abschluss_belege/drei_waende_der_gate_zeile_9906d91439e2.json`), und das ist
hier die richtige Zahl, nicht die aergerliche.

## S38 — Der Kopf, an den die Owner-Karte die vier Bereitschaftsartefakte bindet, ist ueberholt

Owner-Karte `OA-f680f7cc3f` sagt: *„miss die vier Artefakte neu, aber gebunden an den finalen Kopf
ad906a9 erst nach gruenem Schritt 50."* **`ad906a9f6c0820d83879ea922a9241eaefb8d60e` ist nicht mehr
der Kopf.** Gemessen: er ist Vorfahr von HEAD, und dazwischen liegen **fuenfzehn Commits**.

**Das ist mehr als Buchhaltung, weil der Pruefer genau darauf schaut.**
`audit_candidate_matrix._gate_line_error` verlangt `gate_zeile.head == candidate.commit`, und
`candidate.commit` ist `head_commit(repo)` zum Zeitpunkt des Signierens. Ein Artefakt, das an
`ad906a9` gebunden wird, waehrend der getaggte Kopf ein anderer ist, faellt an genau dieser Zeile:
*„a verdict about another head cannot release this one."*

**Was sich zwischen `ad906a9` und HEAD wirklich geaendert hat, nach Art getrennt:**

| Datei | Art |
|---|---|
| `RESTRISIKO_600.md` | Register (nicht digest-befreit — bewegt beide Digests) |
| `audit_artifacts/360/budget_axis_latest.json` | Bereitschaftsartefakt (digest-befreit, `MUTABLE_EVIDENCE_RELS`) |
| `audit_artifacts/360/fuzz_soak_latest.json` | dito |
| `audit_artifacts/360/rust_differential_matrix.json` | dito |
| `tests/test_stille_ruecknahme_position_x_malformation.py` | **echte Testdatei** |

Die drei Artefakte zu sehen ist erwartbar — sie SIND die Messungen. Die Testdatei nicht: sie wurde
in `0159bc7` eingefuehrt (vor `ad906a9`) und in `b28b938` geaendert (**nach** `ad906a9`).

**Ob das eine Nachmessung erzwingt — nein, und zwar belegt.** Die drei Bereitschaftsmessungen fahren
Parser, Rust-Python-Vergleich und Budget-Achsen, nicht die Testsuite; eine Testdatei aendert ihren
Gegenstand nicht. Und die Suite selbst ist ueber den geaenderten Stand gelaufen: die Vollsuite mit
**3957 passed / 24 skipped / 1086 Untertests / RC=0** lief ueber `21669b6`, und `21669b6` liegt
NACH `b28b938`. Von `21669b6` bis HEAD nennt `git diff --name-only` **genau eine Datei**,
`RESTRISIKO_600.md`.

**Daraus folgt eine Aussage, die fuer die Signatur zaehlt:** der jetzige Kopf ist
suite-abgedeckt — nicht weil ich die Suite hier erneut gefahren haette, sondern weil die
Code-Flaeche zwischen dem gemessenen Stand und HEAD nachweislich unveraendert ist. Die Kette ist
`b28b938` → Suite ueber `21669b6` (gruen) → HEAD nur Register-Text.

**Und daraus folgt die praktische Anweisung fuer den, der signiert:** nicht `ad906a9` binden. Den
dann geltenden Kopf binden, seine beiden Digests frisch messen (jeder weitere Registereintrag
bewegt sie) und die Distributions-Digests an ihm neu bauen — `SOURCE_DATE_EPOCH` haengt an der
Commit-Zeit. Registerschluessel `OWNER-KARTE-BINDET-EINEN-UEBERHOLTEN-KOPF-01`.

## S39 — Die Distributionen am jetzigen Kopf, beide Haelften des Byte-Freeze gruen

S38 sagt, wer signiert, muesse die Distributions-Digests am dann geltenden Kopf neu bauen. Fuer den
jetzigen Kopf ist das erledigt, damit dieser Schritt nicht mehr im Signierpfad haengt.

**Gebaut ueber `a5613d3d721d7fcbb81b864ed72b542b227541e2` (dirty 0), `SOURCE_DATE_EPOCH = 1788916069`
(die Commit-Zeit dieses Kopfes):**

| Artefakt | Groesse | sha256 |
|---|---|---|
| `proofbundle-6.0.0.tar.gz` | 2 162 252 B | `b900ce74c4271af9dd120ebc2ee7b4d6f9aa0836d517ebdca320a5dacc8a359f` |
| `proofbundle-6.0.0-py3-none-any.whl` | 542 451 B | `a2b98e337aac78ff7adeb0c8e17768efc255753035434627619ffda1f218b6e9` |

**Beide Haelften des Byte-Freeze, getrennt gefahren und beide gruen:**

* `--check` (Fundament F2): zweimal gebaut, `sha256_a == sha256_b == b900ce74…`, `reproducible: true`.
* `--check-wheel`: das wheel AUS DEM AUSGELIEFERTEN sdist ist byte-identisch mit dem direkt aus dem
  Baum gebauten — `sha256_direct == sha256_from_sdist == a2b98e33…`, `identical: true`.

Die zweite Haelfte ist die, die man vergisst: ein reproduzierbarer sdist sagt nichts darueber, ob das
wheel, das ein Nutzer aus ihm baut, dasselbe ist wie das, das wir veroeffentlichen. Sie war nach dem
ersten Lauf offen und ist jetzt gemessen.

**Ehrliche Grenzen, drei.** (1) Gebaut auf DIESER Maschine mit DIESEM Interpreter — Reproduzierbarkeit
ueber Hosts hinweg ist damit nicht gezeigt, nur ueber zwei Laeufe hier. (2) Die Zahlen gelten fuer
`a5613d3`; **jeder weitere Registereintrag aendert die Commit-Zeit und damit den Epoch, und mit ihm
beide Digests** — sie sind ein Angebot fuer den Fall, dass hier eingefroren wird, kein Dauerwert.
(3) Die Maschinenlage wurde fuer diesen Lauf nicht mitprotokolliert (`b7_messfeld.py` ist ein
Werkzeug des Verwaltungsrepos und liegt in diesem Baum nicht). Fuer eine Digest-Messung ist das
folgenlos — ein Digest ist deterministisch, Last aendert nur die Dauer —, aber es gehoert benannt
statt weggelassen.

**Der Beleg dazu ist geholt und ist PARTIAL, aus demselben Grund wie der zu S37.**
`office/governance/abschluss_belege/byte_freeze_beide_haelften_94a7a0faa45d.json`, gebunden an
`94a7a0faa45d2311af7d192529fbbd8377349c85` mit `--repo /home/konrad/proofbundle`. Vier Gruende,
woertlich dieselben: Pre-Sweep, Klassen-Ledger (zweimal) und Linsenablage fehlen im
content-adressierten Baum, 0 Linsen gegen Boden 3. **Das ist Wand 3 zum dritten Mal an einem
eigenen Beleg** — und es heisst nicht, dass die Messung schlechter ist, sondern dass der Zeuge sie
ueber einem fremden Baum nicht bezeugen KANN. Die Byte-Freeze-Zahlen selbst stehen unabhaengig
davon: sie kommen aus zwei Laeufen von `build_reproducible.py`, deren Ausgabe oben woertlich
zitiert ist und die jeder nachfahren kann.

## S40 — Der Familien-Floor ist fuer S37-S39 NICHT erfuellt, und das gehoert an die Abschnitte selbst

S35 und S36 wurden von drei Linsen aus zwei Familien gegengelesen (`71be4f2e5`). **S37, S38 und S39
haben inzwischen EINE Linse — aus EINER Familie** (Claude, abgelegt und committet als `302f6135a`;
ihr Verdikt und seine Folgen stehen in S42). Der Familien-Floor bleibt damit gerissen, und der Grund
ist gemessen, nicht organisatorisch.

**Der fremdfamiliaere Weg liefert in diesem Fenster nicht.** Zwei Laeufe gegen denselben Host, der
sich als warm meldete und laut `/api/ps` `qwen3.8:27b` geladen hatte:

| Lauf | Eingabe | Ergebnis |
|---|---|---|
| Gegenlesung der Nachtraege | 221 Zeilen Diff, `num_ctx 16384` | nach **1800 s** `TimeoutError`, **null Bytes** |
| Diskriminator, bewusst winzig | drei Saetze, `num_ctx 2048`, `num_predict 200` | nach **300,2 s** `TimeoutError`, **null Bytes** |

Der eigene Prozess hatte in beiden Faellen **0 s CPU-Zeit** — er hing rein am Lesen der Antwort.
**Die Eingabegroesse ist damit als Erklaerung nicht unwahrscheinlich, sondern gemessen widerlegt:**
200 Ausgabetoken verhalten sich wie ein 16384-Token-Kontext. **Die Ursache ist NICHT BESTIMMT**
(Verdraengung durch die Parallelsitzung am selben Host, eine haengende Anfrage in seiner
Warteschlange, oder etwas Drittes); nicht gemessen ist auch, ob ein Neustart es loest.

**Und es gibt keinen Ausweichweg — gemessen, nicht angenommen.** Das System kennt zwei
un-Controller, und nur einer traegt ueberhaupt eine Adresse:

```
vast     base=http://79.161.122.162:60542   warm=True
runpod   base=<leer>                        warm=False
```

Der Familien-Floor ist damit nicht gerissen, weil ich es nicht versucht haette, sondern weil es
**genau EINE fremdfamiliaere Route gibt und das die ist, die nicht liefert**. Das ist ein anderer
Zustand als „nicht geprueft", und er hat eine andere Konsequenz: er ist von dieser Bahn aus nicht
behebbar. Wer den Floor erreichen will, braucht einen zweiten Weg — eine Beschaffungsfrage, keine
Sorgfaltsfrage.

**Was das fuer den Beweiswert dieser drei Abschnitte heisst, ohne Beschoenigung.** Der Zeuge fordert
fuer `NORMAL-3L3I` einen Familien-Floor von **zwei** (`_MIN_FAMILIES`), und
`B7_STANDING_UN_DIVERSITY_DEFAULT_ON` verlangt Vielfalt als Regelfall. Ein Panel aus einer Familie
mindert korrelierte Fehler nicht, es verstaerkt sie — das steht so im Staerke-Kontrakt sc3 des
Zeugen, mit Quelle. **S37, S38 und S39 tragen deshalb keine familienvielfaeltige Gegenlesung, und
diese Zeile ist ihre ehrliche Beschriftung.**

Das entwertet ihre MESSUNGEN nicht — die stehen als ausfuehrbare Kommandos in den Abschnitten und
wurden fuer S35/S36 von einer unabhaengigen Linse Zahl fuer Zahl nachgefahren. Es entwertet die
Aussage „gegengelesen". Wer nach dem Ausfall eine zweite Familie erreicht, sollte die drei
Abschnitte nachziehen; bis dahin gilt hier **PARTIAL_PANEL_EINE_FAMILIE**.

Befund `UN-DIREKTWEG-LIEFERT-IN-DIESEM-FENSTER-NICHT-01`. Registerschluessel
`FAMILIEN-FLOOR-FUER-S37-BIS-S39-NICHT-ERFUELLT-01`.

## S41 — `probe/gatezeile-in-kandidat` traegt nichts, was der Release-Linie fehlt

Der Zweig heisst nach dem Thema dieser Nacht und liegt fuenf Commits vor seinem eigenen Fernstand.
Naheliegender Verdacht: dort liegt Arbeit, die in 6.0.0 gehoert. **Nachgemessen: nein — beide
Commits sind vom Release-Kopf ueberholt.**

**1. `f67f289 fix(mutationstor): ein abgebrochener Lauf ist NICHT null rote Tests.** Der Zweig fuehrt
`_rote_aus_lauf(returncode, stderr)` (Zeile 641). **Der Release-Kopf fuehrt dieselbe Funktion in
einer STAERKEREN Fassung** (Zeile 866): `_rote_aus_lauf(bericht, text, rc)` prueft nicht nur
`rc in _RC_NICHT_MESSBAR`, sondern zusaetzlich die **FORM** des Abbruch-Banners und liest die
JUnit-XML als strukturierte Quelle, bevor sie auf Text zurueckfaellt. Der Kommentar dort nennt den
Fall, den die Zweig-Fassung noch nicht faengt: `pytest.exit()` schreibt ein Banner mit ANDEREM
Wortlaut, und dabei melden Bilanz UND JUnit-XML einen sauberen Lauf, waehrend der toetende Test nie
lief.

**2. `eb09cce fix(byte-freeze): der xfail faellt, weil er angeschlagen hat.** Der Zweig entfernt
einen `xfail(strict=True)` aus `tests/test_byte_freeze_zweite_haelfte.py`. **Der Release-Kopf hat
dort ueberhaupt kein `xfail` mehr** — gemessen: `git show release/600-push-linie:<datei> | grep
xfail` findet nichts, nur die zwei Testfunktionen. Auch das ist also schon da. Passend dazu die
eigene Messung aus S39: `--check-wheel` meldet `identical: true`.

**Folge:** der Zweig braucht nichts, und aus ihm ist nichts zu holen. Der frueher notierte Punkt
„lokal fuenf Commits voraus" ist damit beantwortet statt offen.

**Und die Klasse, die hier fast wieder zugeschlagen haette.** Der erste Blick auf den Zweig-Diff
las sich wie „ein echter Korrektheitsfix fehlt der Release-Linie" — das waere ein Befund gewesen,
und ein falscher. Es ist woertlich die Klasse aus dem Gedaechtnis dieser Bahn: *eine Aussage ueber
einen KOPF wird am KOPF gemessen, nie aus einem Diff abgeleitet* („Zweig X fixt Y" heisst nicht
„Kopf Z hat Y nicht"). Diesmal stand die Gegenfrage vor der Meldung, und sie hat sie kassiert.
Registerschluessel `PROBEZWEIG-IST-UEBERHOLT-NICHT-VORAUS-01`.

## S42 — Wand 2 ist KEINE Owner-Entscheidung: ich habe dieselbe Klasse begangen, die ich eine Seite vorher benannt habe

> ⛔ **DIESER ABSCHNITT IST WIDERLEGT — siehe S49.** Sein Hauptfund („der Zeuge fuehrt ein Verdikt")
> stimmt; sein SCHLUSS nicht. Der Zeuge ist nicht der Erzeuger der Gate-Zeile — das ist das
> Workflow-Laufergebnis, dessen `verdict` in Name UND Wertform mit `_GATE_VERDICTS_PASS`
> deckungsgleich ist (ausgefuehrt gegen `_gate_line_error`, vier Faelle). Es driften genau **drei
> Feldnamen**, nicht das Urteil. Wand 2 bleibt eine Festlegung. Der Abschnitt bleibt stehen, weil
> die Punkte 2-5 seiner Gegenlesung (`unsigned`, drei Pfade in `MUTABLE_EVIDENCE_RELS`) tragen.

Eine Gegenlesung von S37/S38/S39 (`VERDIKT: REJECT`, fuenf Punkte) hat den schwersten Fehler dieser
Nacht gefunden, und er sitzt in der zentralen Aussage. **Alle fuenf Punkte habe ich selbst
nachgemessen; alle fuenf treffen.**

### Der Hauptfund: der Zeuge FUEHRT ein Verdikt, ich habe nur das falsche Feld gezaehlt

S35 mass „0 von 412 Belegen tragen ein nicht-leeres `verdict`" und schloss daraus, der Zeuge fuehre
gar kein Verdikt — also fehle eine Abbildung von `strength` auf ein Urteil, und die sei eine
**Owner-Festlegung**. Nachgemessen:

```
Belege 416 · mit nicht-leerem verdict_tag: 414
  WITHSTANDS_DEEPGATE 135 · PARTIAL_GATE_NO_WITHSTANDS 269 · WITHSTANDS_BERKELEY 6 · REFUTED 4
```

`b7_berkeley_gate_receipt.verdict_tag()` (Zeilen 384-411) **rechnet genau diese Abbildung** —
`strength != "FULL"` ergibt `PARTIAL_GATE_NO_WITHSTANDS[...]`, sonst
`WITHSTANDS_DEEPGATE[v4/sc1/DEEP-6L7I/FULL]` — und schreibt sie in **jeden** Beleg.

**Ich habe nach einem Feld namens `verdict` gesucht und aus seinem Fehlen auf das Fehlen der Sache
geschlossen. Das ist woertlich die Klasse, die ich als Wand 1 benannt hatte, eine Seite vorher, im
selben Text.**

### Und es sind DREI Drifts, nicht eine — die Wand wird dadurch schaerfer, nicht kleiner

| | 2bedone (Erzeuger + eigener Konsument) | proofbundle (Pruefer) |
|---|---|---|
| Feldname | `verdict_tag` | `verdict` |
| Vergleichsart | `startswith(("WITHSTANDS_DEEPGATE[", …))` (Z. 637-638) | `not in _GATE_VERDICTS_PASS`, **exakt** (Z. 1178) |
| Wertform | `WITHSTANDS_DEEPGATE[v4/sc1/DEEP-6L7I/FULL]` | die blanke Zeichenkette `WITHSTANDS_DEEPGATE` |

Selbst ein woertlich kopierter Tag faellt also durch — der Klammerzusatz allein reicht. **Wand 1 hat
damit nicht drei Felder, sondern vier** (`workflow_datei`, `workflow_sha256`, `head`, `verdict`),
und die 2bedone-Seite prueft dieselbe Sache mit einer ANDEREN Vergleichsart als die
proofbundle-Seite.

### Was das an der Owner-Frage aendert, und es ist der zweite Umbau in einer Nacht

**Wand 2 war nie Owner-Gebiet.** Sie ist ein Handgriff derselben Art wie Wand 1. Damit gilt:

> **Nur Wand 3 ist Owner-Gebiet** — soll die Pruefmechanik aus einem ANDEREN Baum gelesen werden
> duerfen als dem beurteilten. Das ist EINE Frage, nicht zwei.

Die Gegenlesung fuegt dazu einen Nebenbefund an der UND-Ketten-These an, und auch der trifft: **Wand
3 allein zu schliessen aendert sehr wohl etwas Reales** — es kippt `strength` von PARTIAL auf FULL,
unabhaengig von Wand 1. Nur die engere Frage „ergibt sich eine SIGNIERBARE Gate-Zeile" bleibt eine
Kette. S37 hat die Kette also richtig beschrieben, ihren Gegenstand aber zu weit gefasst.

### Vier weitere Punkte derselben Gegenlesung, alle nachgemessen und alle angenommen

**Weg C ist NICHT kostenlos.** `ART_UNSIGNED = "unsigned"` (Z. 330) steht **nicht** in
`_ART_DATA_BLOCKED_STATES = {ART_UNMEASURABLE_HERE}` (Z. 337). Ein unsigniertes Artefakt ergibt
damit hartes **FAIL**, nicht DATA_BLOCKED; C6.2/C6.3/C8.2 sind keine informativen Pruefungen,
`ready_before_binding` verlangt `counts[FAIL] == 0`, und der Lauf endet mit **exit 1**. Richtig
bleibt „verlangt keinen Bau und keinen Widerruf" — falsch war „kostet nichts": die Matrix wird rot,
und ob der Owner das ueberstimmt, ist eine zweite Frage.

**S38s Begruendung war sachlich falsch, ihr Ergebnis nur zufaellig richtig.** Ich schrieb, die drei
Bereitschaftsmessungen fuehren „Parser, Rust-Python-Vergleich und Budget-Achsen, nicht die Suite".
`scripts/budget_axis_measurement.py` (Z. 44-48) **importiert `tests/test_budget_kostenkurve` als
Modul und ruft dessen Zusicherungen auf** — es faengt sogar `Skipped`/`Failed` aus
`_pytest.outcomes`. Es fuehrt also eine Testdatei aus. Dass die Schlussfolgerung trotzdem haelt,
liegt allein daran, dass die geaenderte Datei eine ANDERE war. **Und das Bittere: ich hatte diese
Datei in derselben Nacht vollstaendig gelesen und den Import zitiert.**

**S39 fehlt eine vierte ehrliche Grenze, und es sind zwei.** (a) `--check` baut zweimal **mit
Isolation als Standard** — beide Laeufe koennen ihre eigene Werkzeugkette ziehen. Zwei Laeufe
Sekunden hintereinander zeigen Determinismus gegen EINE Momentaufnahme der Werkzeugkette, nicht
Stabilitaet gegen deren Drift (reproducible-builds.org fuehrt genau das als Risiko). (b) Fuer das
**wheel** gibt es ueberhaupt keinen Zweimal-Bau-Vergleich: `measure_wheel_from_sdist` baut je
EINMAL direkt und aus dem sdist und vergleicht nur diese beiden, und `normalize_wheel` behaelt die
ZIP-Reihenfolge **bewusst** bei. Ein Nichtdeterminismus in der Paketierung selbst faende dieser
Test nie.

**„Vier Bereitschaftsartefakte" sind DREI Dateien.** `MUTABLE_EVIDENCE_RELS` nennt genau drei Pfade,
und `_soak_artifact()` sagt woertlich: *„EINMAL gelesen und fuer beide Pflichten (C6.2/C6.3)
derselbe"*. C6.2 und C6.3 teilen sich `fuzz_soak_latest.json`; ein Signieren betrifft beide. Meine
Vierer-Zaehlung ueberzeichnete die Zahl unabhaengiger Entscheidungen.

### Die Bilanz dieser Nacht, ohne Beschoenigung

Fuenf Runden Korrektur an einem Befund, und **die schwerste kam von einer Linse, nicht von mir** —
zum dritten Mal. Der Fehler ist jedes Mal derselbe Typ: **ich messe eine FORM (heisst das Feld so?)
und schliesse auf die EIGENSCHAFT (gibt es die Sache?).** Ich habe diese Klasse in derselben Datei
benannt und sie danach begangen.

**Was daran GEMESSEN ist und was nicht, weil der Unterschied hier besonders zaehlt.** Gemessen ist
das MUSTER: die Klasse steht benannt im Text, und danach steht die Instanz — zweimal heute, beide
Male mit Datei und Zeile nachweisbar. **NICHT GEMESSEN ist die Erklaerung**, eine benannte Klasse
fuehle sich erledigt an und greife deshalb nicht mehr; das ist eine Vermutung ueber mich selbst,
n=2, und sie gehoert nicht als Befund verkauft. Was aus dem Muster unabhaengig von jeder Erklaerung
folgt, ist die Abhilfe: **eine Klasse braucht neben ihrem Namen eine AUSFUEHRBARE Frage.** Hier
waere es eine Zeile gewesen — die Feldnamen des Bestands auszaehlen statt einen Namen abzufragen.
Registerschluessel `WAND-2-WAR-NIE-OWNER-GEBIET-DIESELBE-KLASSE-EINE-SEITE-SPAETER-01`.

## S43 — Die Vorab-Quittung ist GUELTIG, sie bindet nur den falschen Baum

Ich habe diese Quittung die ganze Nacht als „sagt `FIX_FIRST`" mitgetragen, aus dem Gedaechtnis.
**Gemessen stimmt das nicht.** `audit_artifacts/600/pre_tag_receipt_v6.0.0.json`:

```
schema  b7n0de.pre_tag_audit_receipt.v1   version 6.0.0
audit_exit_code      0                      produced_at 2026-09-06T20:27:33Z
subject_tree_digest  877cd4f98ffc8924…      runner_identity b7n0de-release-runner
signature + signer_pubkey  vorhanden
```

Sie traegt **kein** `verdict`-Feld und **keinen** Fehlschlag: `audit_exit_code` ist **0**. Der
`FIX_FIRST`-Satz, den ich ihr zugeschrieben habe, gehoert zu einer ANDEREN Datei (dem Gate-Ergebnis
`gate_result_600_lauf4b_FIX_FIRST.json`). Zwei Artefakte, ein Gedaechtniseintrag — genau die
Verwechslung, gegen die dieses Register sonst argumentiert.

**Gegengeprueft mit dem echten Verifizierer, beide Richtungen:**

```
verify_receipt gegen den HEUTIGEN Baum : False
  "receipt subject_tree_digest does not bind THIS tree
   ('877cd4f9…' != 'e24dc75c…')"
verify_receipt gegen den EIGENEN Baum  : True
  "signed, tree-bound, successful-audit receipt verified"
```

**Die Quittung ist also in Ordnung — sie ist nur drei Tage alt.** Sie bindet den Baum vom
06.09. 20:27Z, und jeder Registereintrag dieser Nacht hat den Baum bewegt. Der Verifizierer lehnt
sie aus genau EINEM Grund ab, und es ist nicht das Urteil, sondern die Bindung.

**Was daraus fuer die Kette folgt, und es ist eine gute Nachricht.** Die Vorab-Quittung braucht
keinen neuen Audit-BEFUND — der bestehende ging mit Exit 0 aus. Sie braucht eine **Neuausstellung
ueber den dann finalen Kopf**: derselbe Vorgang, neuer `subject_tree_digest`, neue Signatur. Das ist
ein Schritt der Signaturrunde und kein offener Defekt.

**Und die vierte Instanz derselben Sache in einer Nacht.** Viermal habe ich eine mitgetragene
Annahme fuer gemessen gehalten: der Zeuge fuehre kein Verdikt (er fuehrt `verdict_tag`) · der
Probezweig sei der Release-Linie voraus (er ist ueberholt) · die Bereitschaftsartefakte seien vier
(es sind drei Dateien) · und jetzt, die Vorab-Quittung sage `FIX_FIRST` (sie sagt Exit 0). **Jede
dieser Annahmen kostete eine Zeile im Gedaechtnis und war in unter zwei Minuten pruefbar.**
Registerschluessel `VORAB-QUITTUNG-IST-GUELTIG-NUR-DER-BAUM-IST-ALT-01`.

## S44 — Fuer die Neuausstellung der Vorab-Quittung gibt es einen schluessellosen Weg, und er ist genau fuer diese Auflage gebaut

S43 endet mit: die Quittung braucht eine Neuausstellung ueber den finalen Kopf. Offen blieb, ob das
ueberhaupt von hier aus geht — der private Schluessel liegt beim Owner. **Gemessen: es geht, in zwei
Haelften, und der Weg steht seit Langem im Werkzeug.**

`scripts/pre_tag_receipt.py` kennt **drei** Modi. Der signierte 9-Feld-Kontext ist in allen drei
identisch; nur der Ort der Signatur unterscheidet sie (Docstring Z. 6-20, woertlich):

| Modus | Was er tut | Wo der Schluessel ist |
|---|---|---|
| `inline` (Standard, `--privkey-file`) | Kontext bauen, hier signieren, Quittung schreiben | beim Laufenden |
| **`emit`** (`--emit-payload P --context-out C`) | schreibt `canonical_bytes(context)` nach P und den Kontext nach C. **„NO private key is read."** | **nirgends hier** |
| **`assemble`** (`--assemble --context-in C --sig-file S --signer-pubkey B --out R`) | packt Kontext + Signatur + Pubkey zur Quittung, **prueft die Signatur selbst und VERWEIGERT bei Abweichung** | nirgends hier |

Das Werkzeug nennt die Aufteilung beim Namen: *„the Farmer emits, the key-holder (Mac) signs P, the
Farmer assembles. The private key never reaches the Farmer."*

**Das ist wortgleich die Auflage des Owners** („die Signatur bleibt mein Akt, die Sessions fassen den
Schluessel nicht an"). Es muss also nichts gebaut und nichts entschieden werden — der Ablauf
existiert:

1. **Farmer:** `pre_tag_receipt.py --emit-payload P --context-out C` ueber den finalen Kopf. Kein
   Schluessel im Spiel.
2. **Mac (Owner):** `P` mit dem Release-Schluessel signieren, Signatur nach `S`.
3. **Farmer:** `--assemble --context-in C --sig-file S --signer-pubkey B --out R`. Der Schritt
   **prueft die Signatur gegen den Kontext und schreibt bei Abweichung KEINE Datei** — fail-closed,
   eine kaputte Paarung wird nie zur Quittung.

**Ehrliche Grenze:** ich habe die drei Modi aus dem Werkzeug GELESEN und die Aufteilung der
Schluesselhoheit daraus abgeleitet; **ich habe den `emit`/`assemble`-Weg NICHT ausgefuehrt**. Was
gemessen ist: die Modi existieren mit diesen Schaltern, der `assemble`-Pfad deklariert seine
Selbstpruefung, und die bestehende Quittung verifiziert gegen ihren eigenen Baum sauber (S43). Was
NICHT gemessen ist: ob der Lauf ueber den finalen Kopf durchlaeuft — das gehoert in die
Signaturrunde und nicht davor.

**Was das an der Lage aendert:** die Vorab-Quittung war in meinen Berichten ein offener Punkt mit
unklarem Weg. Sie ist ein **Ablaufschritt mit vorhandenem Werkzeug**. Registerschluessel
`VORAB-QUITTUNG-HAT-EINEN-SCHLUESSELLOSEN-ZWEI-HAELFTEN-WEG-01`.

## S45 — Der laufende Soak bindet einen 30 Commits alten Kopf, und das ist gemessen folgenlos

Zwei getragene Annahmen ueber den 24h-Soak nachgemessen. **Eine war um zwei Stunden falsch, die
andere fuehrte auf eine echte Frage — die sich dann aufloest.**

**Die Zeit.** Ich habe „landet ~16:00Z" berichtet. Gemessen (PID 2640683, `etimes`):

```
Start        2026-09-08T14:00Z      Stand 2026-09-09T02:09Z (12 h 08 min gelaufen)
24h-Ende ca. 2026-09-09T14:00Z      noch 11 h 51 min
```

**Die Bindung, und hier wurde es kurz ernst.** Der Soak-Arbeitsbaum steht auf
`c08e4650eca1ebd6df05c9836ec80cecb4e6b32e` (dirty 0) — dem Fernstand. Der Release-Kopf ist
**30 Commits weiter**, und der Unterschied ist NICHT nur Doku: genau **eine** `src/`-Datei weicht
ab, und es ist ausgerechnet `src/proofbundle/relation.py` — die Datei, die den P1-Fix dieser Runde
bekam (S25, Karte `OA-dccd141d78`: die still uebersprungene Ruecknahme, die `safeForAutomation` von
false auf true und den Ausgang von 3 auf 0 kippen liess).

**Die Frage war also berechtigt: fuzzt der Soak einen Parser ohne den Fix?** Nachgemessen mit der
Vorfahren-Pruefung von `0159bc7` gegen `c08e4650`: **NEIN — der Fix ist nicht im Soak-Baum.**

**Und dann loest es sich auf, funktionsgenau.** Der Soak zieht seine Ziele aus
`discover_python_verify_functions()` — 64 Funktionen, davon **zwei** aus `relation`. Ein
AST-Vergleich beider Baeume:

| Funktion | c08e4650 → HEAD | vom Soak angefasst? |
|---|---|---|
| `successor_warning` | **VERSCHIEDEN** (`f3a44619…` → `a2421d08…`) | **nein** — kein `verify_*`-Ziel |
| `validate_relationships` | GLEICH (`76ab5311…`) | ja |
| `verify_relationship_edges` | GLEICH (`08654dbe…`) | ja |

**Die geaenderte Funktion ist kein Soak-Ziel, und die beiden Soak-Ziele sind byte-gleich.** Der
laufende Soak fuzzt in `relation` also exakt denselben Code, der auch im Release-Kandidaten steht.
Die veraltete Kopf-Bindung ist fuer SEINE Aussage folgenlos — nicht weil es egal waere, sondern weil
es nachgemessen ist.

**Was trotzdem stehen bleibt, und es ist eine Grenze, keine Entwarnung.** Der Vergleich deckt
`relation.py` ab, weil dort der einzige `src/`-Unterschied liegt. Er sagt nichts darueber, ob ein
SPAETERER Commit vor dem Tag wieder eine gesoakte Funktion aendert — dann waere dieselbe Pruefung
erneut faellig. **Die Regel, die daraus folgt:** wer den Soak als Beleg heranzieht, vergleicht die
`src/`-Differenz zwischen Soak-Baum und Tag-Kopf und prueft, ob eine GESOAKTE Funktion darin liegt.
Ein Blick auf die Commit-Zahl genuegt nicht — 30 Commits klangen alarmierend und waren es nicht.

Registerschluessel `SOAK-BINDET-ALTEN-KOPF-ABER-DIE-GESOAKTEN-FUNKTIONEN-SIND-GLEICH-01`.

## S46 — Der CI-Stand am Fernkopf, selbst gemessen: zwei von sechs rot, und der rote ist der bekannte P0

Ich habe den CI-Stand die ganze Runde aus dem Gedaechtnis zitiert („22 von 25 Jobs gruen"). Jetzt
selbst abgefragt — **und die erste Abfrage log**.

**Die Abfrage ueber den ZWEIGNAMEN liefert nichts:**

```
gh run list --branch release/600-push-linie   ->  []
```

**Die Abfrage ueber den SHA liefert sechs Laeufe:**

```
40 Laeufe abgerufen · davon am Fernkopf c08e4650: 6
Zweige in der Liste: fix/deepgate600/integration-600 (38) · main (2)
```

**GitHub schreibt die Laeufe dem ANDEREN Zweignamen zu.** Beide Zweige zeigen auf denselben SHA
(im Register mehrfach notiert), und der Dienst haengt seine Laeufe an den Namen, unter dem gepusht
wurde. Wer nach `release/600-push-linie` fragt, bekommt eine leere Liste und koennte daraus „keine
CI" lesen. **Das ist woertlich die Klasse „ein leeres Ergebnis aus dem falschen Schluessel ist kein
leerer Bestand"** — sie steht seit gestern im Gedaechtnis dieser Bahn, und genau deshalb hat sie
diesmal nur eine Abfrage gekostet statt eines Fehlschlusses im Bericht.

**Der gemessene Stand am Fernkopf `c08e4650`:**

| Lauf | Ergebnis |
|---|---|
| `published-artifact-gate` | **failure** |
| `CI` | **failure** |
| `demo-reproducible` | success |
| `fork-pr-isolation` | success |
| `release-integrity` | success |
| `CodeQL` | success |

**Beide roten sind erklaert und keiner ist neu.** `published-artifact-gate` scheitert am P0
`L6-600-01` — die Suite aus dem AUSGELIEFERTEN sdist bricht mit `Interrupted: 1 error during
collection` ab. Dieser Fix liegt seit dieser Runde im Arbeitsbaum und ist **nicht uebertragen**,
also muss der Fernkopf ihn rot zeigen. `CI` traegt die Mutations-Jobs, deren Rot im Register bereits
als Runner-Abbruch (exit 143) und nicht als Defekt eingeordnet ist.

**Ehrliche Grenze:** das sind WORKFLOW-Laeufe, nicht die einzelnen Jobs darin. Die frueher zitierte
Job-Zahl („22 von 25") ist eine andere Granularitaet und stammt nicht aus dieser Messung; ich fuehre
sie hier nicht als bestaetigt. Was gemessen ist: sechs Laeufe am Fernkopf, zwei rot, beide mit
bekannter Ursache.

**Fuer den Tag heisst das:** der Fernkopf zeigt rot, solange der P0-Fix nicht uebertragen ist — das
ist erwartet und kein neuer Befund. Wer die Kette beurteilt, vergleicht den CI-Stand des DANN
gepushten Kopfes, nicht den von `c08e4650`. Registerschluessel
`CI-LAEUFE-HAENGEN-AM-ANDEREN-ZWEIGNAMEN-DESSELBEN-SHA-01`.

## S47 — Schritt 5 der Anweisung ist nicht erreichbar: schon das EMITTIEREN verlangt die Gate-Zeile

Nachdem S42 zeigte, dass ich die Owner-Anordnung aus einer Zusammenfassung statt aus der Quelle
gefuehrt hatte, habe ich die Uebernahme-Anweisung **vollstaendig gelesen** (32 Zeilen, Anfang bis
Dateiende). Sie enthaelt eine zweite Pflicht, die ich uebersprungen hatte — und deren Pruefung den
Halt schaerfer macht als jede bisherige Formulierung.

**Die Anweisung, Schritt 5 (Zeile 19), woertlich:** *„Kanonische Bytes fuer die
Bereitschaftsartefakte C6.2, C6.3, C8.2 und das Findings-Register emittieren, Pfade und sha256 im
Blatt, dann Halt BLOCKED_OWNER_DECISION_REQUIRED vor der Signatur. Der Owner signiert am Mac, danach
assemblieren."*

**Ich habe die ganze Runde „nicht signierbar" berichtet und dabei uebersehen, dass das EMITTIEREN
ein eigener, VORGELAGERTER Schritt ist** — der Schritt, der dem Owner ueberhaupt erst die Bytes
liefert, die er signieren soll.

**Nachgeholt und gemessen.** `sign_readiness_artifact.py` hat den schluessellosen Weg
(`--emit-payload` / `--context-out`, wie die Vorab-Quittung). Aufgerufen fuer C6.2 mit den frischen
Distributions-Digests, ohne Gate-Zeile:

```
emit mode needs: --producer-tool-version, --input-digest, --gate-zeile-aus-verdikt
```

**Das EMITTIEREN verlangt die Gate-Zeile selbst.** Sie geht in den signierten Rumpf
(`build_body` setzt `body["gate_zeile"]`), und die kanonischen Bytes sind der Rumpf — ohne sie gibt
es keine Bytes, nicht nur keine Signatur.

**Damit ist der Halt praeziser verortet als bisher.** Er liegt nicht „vor der Signatur", sondern
**vor dem Emittieren** — also einen Schritt frueher als die Anweisung ihn vorsieht. Der Owner kann
derzeit **nichts zum Signieren bekommen**, nicht nur nichts signieren. Das ist keine Verschaerfung
der Lage, sondern eine genauere Beschreibung derselben Lage: dieselbe eine Ursache (die Gate-Zeile),
aber eine Stufe frueher wirksam, als ich berichtet habe.

**Was das fuer die Abgabe heisst (Zeile 32):** *„Die letzte Meldung vor der Signatur nennt die Pfade
und sha256 der emittierten Bytes."* Diese Pfade kann es heute nicht geben. Die Meldung nennt
stattdessen den Grund an der Stelle, an der er wirkt — und das ist die ehrliche Form dieser Zeile,
nicht ihre Umgehung.

**Zwei uebersprungene Pflichten aus derselben Wurzel.** Die Meldung auf die Signaturkarte
(Zeile 20/28, nachgeholt als `OA-314aa3b04f`) und das Emittieren (Zeile 19, hier gemessen). Beide
standen in der Quelle, beide fehlten in meiner mitgetragenen Fassung. Registerschluessel
`SCHRITT-5-NICHT-ERREICHBAR-DAS-EMITTIEREN-VERLANGT-DIE-GATE-ZEILE-01`.

## S48 — Meine vier Claude-Linsen dieser Nacht waren adversarial und liefen auf Sonnet; der Standard verlangt Opus

Nach dem Fund aus S42 („Anordnung aus der Zusammenfassung statt aus der Quelle") habe ich den
Standard gelesen, den ich die ganze Nacht zitiert hatte, ohne ihn je zu oeffnen:
`kraxo/00_standards_regeln/STANDARD_modellvielfalt_gate_20260902.md`, 33 Zeilen, vollstaendig.

**Was mich entlastet, weil es geprueft ist.** Zeile 25 verlangt vier Tauglichkeitsproben VOR der
ersten Anwendung von Sonnet. Sie liegen vor: `office/governance/linsen_tauglichkeit.jsonl` fuehrt
`claude-sonnet-5`, Familie `claude`, `P1_FORM` / `P2_GATE_META` / `P3_EHRLICHKEIT` / `P4_SPIEGEL`
alle bestanden, `tauglich: true`, gemessen 2026-09-08T11:05:46Z. Und meine Familienzaehlung stimmt
mit Zeile 29: *„Sonnet neben Opus ist eine Familie, nicht zwei."* Auch mein Umgang mit dem Ausfall
war standardkonform — Zeile 7: *„Faellt eine fremde Familie aus, wird sie als nicht gelaufen
protokolliert, ein Ersatz aus der Mehrheitsfamilie ist verboten, der Lauf endet sichtbar als
PARTIAL."* Genau so steht es in S40.

**Was ich verletzt habe.** Zeile 27, woertlich: *„Adversariale Linsen, Sweep gegen sich selbst,
Zusicherungen falsifizieren, Riegel pruefen, Fangnachweise bewerten, bleiben bei Opus."*

**Alle vier Claude-Linsen dieser Nacht liefen auf Sonnet, und alle vier waren adversarial.** Ihre
Auftraege beginnen woertlich mit „Du bist eine FALSIFIKATIONS-LINSE" und verlangen: den Gegenfall
konstruieren, pruefen ob eine Zusicherung mehr behauptet als ihre Messung traegt, finden was FEHLT,
beurteilen ob eine Einteilung eine bequeme Erzaehlung ist. Das ist Punkt fuer Punkt die Liste aus
Zeile 27, nicht Form- oder Beleg-Arbeit.

**Und der zweite Teil derselben Zeile ist ebenfalls verletzt:** *„Die Zuordnung einer Linse zu einer
Klasse steht im Linsen-Auftrag und im Beleg, nicht im Gedaechtnis."* Meine vier abgelegten
Linsen-Artefakte nennen ihre Klasse nirgends.

**Woher der Fehler kam, und das entschuldigt ihn nicht.** Die Umgebung weist bei substanzieller
Arbeit auf „Linsen = CLAUDE-Subagenten (model='sonnet')" hin, und ich bin dem gefolgt. Der Standard
des Owners sagt etwas Engeres, und **Owner steht ueber Kontext** — genau diese Rangfolge ist die
erste Zeile der eigenen Regeln. Ich habe einen Hinweis der Werkzeugumgebung ueber eine Owner-Regel
gestellt, ohne den Widerspruch auch nur zu bemerken.

**Was das fuer die Funde dieser Nacht heisst, nuechtern und ohne Selbstentlastung in beide
Richtungen.** Die Sonnet-Linsen haben real geliefert — eine von ihnen fand den schwersten Fehler der
Runde (`verdict_tag`, S42), zwei weitere trugen REJECT-Verdikte mit Datei-und-Zeile-Belegen, die
sich alle nachmessen liessen. Die Funde sind damit **nicht entwertet**: sie sind gemessen, nicht
geglaubt. Entwertet ist die **Stufe des Panels** — ein adversariales Panel auf der falschen
Modellstufe ist nach diesem Standard kein volles Panel, unabhaengig davon, was es gefunden hat.

**Und die unbequeme Gegenprobe:** haette die Sonnet-Linse den `verdict_tag` NICHT gefunden, waere
die falsche Owner-Frage stehengeblieben. Der Standard existiert genau fuer dieses Risiko. Dass es
diesmal gutging, ist kein Argument gegen ihn.

**Folge fuer die Beschriftung:** S37-S47 tragen bereits `PARTIAL_PANEL_EINE_FAMILIE`; dazu kommt
jetzt, dass die vorhandene Familie ihre adversarialen Linsen auf der falschen Stufe gefahren hat.
Wer sie nachziehen will, faehrt sie auf Opus und deklariert die Klasse im Auftrag UND im Beleg.
Registerschluessel `ADVERSARIALE-LINSEN-AUF-SONNET-STATT-OPUS-01`.

## S49 — S42 ist widerlegt: ich habe den Erzeuger der Gate-Zeile nie gemessen, sondern einen Nachbarn

Eine adversariale Linse auf **Opus** (Klasse im Auftrag UND im Beleg deklariert, Abhilfe zu S48) hat
S42 mit `VERDIKT: REJECT` beantwortet. **Ich habe jeden ihrer Punkte selbst nachgemessen; der
Hauptpunkt trifft, und er dreht die Aussage der ganzen Nacht zurueck.**

### Was ich falsch gemacht habe, in einem Satz

S42 verglich `_GATE_VERDICTS_PASS` mit `verdict_tag` aus den **Zeugen-Belegen** — und der Zeuge ist
gar nicht der Erzeuger der Gate-Zeile. Der Erzeuger ist
`scripts/b7_deepgate_gate_zeile.py::messen()`, gespeist aus dem **Laufergebnis des Workflows**. Ich
habe zwei Flaechen verglichen, die nie miteinander sprechen, und ihren Unterschied „Drift" genannt.

### Die Kette, jedes Glied an der Quelle gelesen

| Glied | Datei:Zeile | Was dort steht |
|---|---|---|
| Der Workflow spricht das Urteil | `deepgate_600_lauf3/berkeley_gate_workflow_600.js:312` | `verdict: {enum: ['WITHSTANDS_DEEPGATE','FIX_FIRST','BLOCKED']}` — **blank** |
| Der Erzeuger uebernimmt es woertlich | `b7_deepgate_gate_zeile.py:250-258` | `if "verdict" in gj: z["verdict"] = roh` — und urteilt ausdruecklich NICHT |
| Das Signaturwerkzeug kopiert die Zeile | `sign_readiness_artifact.py:193-208` | `notes.gate_zeile` **aus dem Verdikt-JSON**, „refusing to invent one" |
| Der Pruefer liest sie | `audit_candidate_matrix.py:315` | `_GATE_VERDICTS_PASS = {"WITHSTANDS_DEEPGATE"}` — **blank** |

`b7_deepgate_gate_zeile.py:242-245` sagt die Arbeitsteilung woertlich: *„Dieses Werkzeug urteilt
nicht und filtert nicht … Die Allowlist liegt beim PRUEFER der anderen Bahn
(`_GATE_VERDICTS_PASS`), und das ist die richtige Seite."* Das ist keine Drift, das ist ein
begruendeter Schnitt.

### Ausgefuehrt, nicht verglichen — vier Faelle gegen `_gate_line_error`

Beide Haelften geladen (`messen()` aus dem `deepgate-version`-Worktree, `_gate_line_error` aus
`pb_pushlinie`) und auf dem echten Laufergebnis `gate_result_600_lauf4b_FIX_FIRST.json`
(`verdict='FIX_FIRST'`, `head=917edc695b28`) gefahren:

```
1. wie der Erzeuger sie liefert     -> gate_line_unbound: workflow_datei=None, workflow_sha256=None, head=None
2. NUR die drei Namen angeglichen   -> gate_line_unbound: verdict 'FIX_FIRST' is not a pass
3. Namen + verdict='WITHSTANDS_DEEPGATE' -> gate_line_unbound: attests head 917edc695b28 but artifact binds None
4. mit einem Zeugen-verdict_tag     -> gate_line_unbound: 'WITHSTANDS_DEEPGATE[v4/sc1/DEEP-6L7I/FULL]' is not a pass
```

**Fall 2 ist der Beweis:** sobald nur die drei Namen stimmen, ist das Urteil das einzige, was noch
zaehlt — und es wird an derselben Zeichenkette gemessen, die der Erzeuger schreibt. **Null Drift in
der Wertform.** Fall 4 zeigt umgekehrt, dass genau der Wert, den S42 fuer den richtigen hielt,
abgelehnt wird.

### Was von S42 bleibt: drei Feldnamen, und nur die

| Der Pruefer verlangt | Der Erzeuger schreibt | Inhalt |
|---|---|---|
| `gate_version` | `gate_version` | `v4` ✔ |
| `modus` | `modus` | `DEEP 6L/7I` ✔ |
| `verdict` | `verdict` | `FIX_FIRST` ✔ (Form und Name deckungsgleich) |
| `workflow_datei` | `workflow_path` | vorhanden, Name driftet |
| `workflow_sha256` | `workflow_digest` | vorhanden, Name driftet |
| `head` | `verdikt_head` | vorhanden, Name driftet |

Drei Namen, drei richtige Inhalte. Das ist genau die Vorgabe, die am 09.09. an un_echoXX ging
(`20260909T0145Z__un_echoXX__gate_zeile_vorgabe_vier_felder_drei_drifts.md`) — **sie war richtig,
und S42 hat sie hinterher falsch begruendet.**

### Warum „einfach angleichen" der Defekt waere, gegen den ein Test steht

`tests/test_freigabe_evidenz_provenienz_l5_g7_02.py:281-288` fuehrt den Fall
`gate_zeile_verdikt_traegt_erlaubtes_als_praefix` mit dem Wert `WITHSTANDS_DEEPGATE_PARTIALLY` —
nachgetragen am 07.09. nach einer gemessenen Abdeckungsluecke, weil die Mutation
`not in _GATE_VERDICTS_PASS` → `.startswith(...)` die ganze Matrix ueberlebt hatte. **Gefahren:
49 passed, RC=0.** Ein Pruefer, der den Zeugen-Tag per Praefix akzeptierte, liesse „teilweise
standgehalten" als Standhalten durch.

### Wand 2 stand richtig — nur ihre Begruendung war falsch

Nicht *„der Zeuge fuehrt kein Verdikt"* (das war S35s Fehler, S42 hat ihn zu Recht korrigiert),
sondern: **der Zeuge ist nicht der Erzeuger der Gate-Zeile, und ihn dazu zu machen hiesse zu
entscheiden, dass ein Receipt-`FULL` als Workflow-`WITHSTANDS_DEEPGATE` gilt.** Die beiden Woerter
sind nicht dasselbe:

* Workflow-`WITHSTANDS_DEEPGATE` (`berkeley_gate_workflow_600.js:306`): **null bestaetigte Funde
  UND** RT-01..RT-04 je ausdruecklich angegriffen und fail-closed bestaetigt.
* Zeugen-`strength: FULL` (`b7_berkeley_gate_receipt.py:83-87`): vier Komponenten plus Linsen-Boden
  — **kein RT-Ziel**. Gemessen: `rt_targets_confirmed` in **0 von 418** Belegen, `head` ebenso 0/418.

Sie gleichzusetzen laesst die RT-Bedingung fallen und aendert die Zulassung **jeder**
freigabeentscheidenden Pruefung. Das ist eine Festlegung, und sie ist bereits getroffen:
Owner-Anordnung `OA-638966a598`, Option A. **Wand 2 ist damit weder Drift noch offen.**

### Der Fangnachweis, den S42 nicht hatte

S42 enthaelt keinen: er zaehlt Feldnamen mit einem `Counter`. Das ist woertlich Form statt
Eigenschaft — die Klasse, die derselbe Abschnitt als Lehre formuliert. Gefallen waere er an drei
Laeufen von je unter fuenf Sekunden: `_gate_line_error` mit einer echten Zeile, `messen()` auf einem
echten Laufergebnis, und dem Test oben.

### Und der Halt liegt noch frueher, als S47 sagte

Gemessen ueber `office/governance/**/gate_result*.json`: **es gibt im ganzen System drei
Workflow-Laufergebnisse.** Zwei tragen `head=049b3195`, eines `head=917edc69`; die Urteile sind
`FIX_FIRST`, `UNADJUDICATED`, `FIX_FIRST`; genau **eines** traegt ueberhaupt eine
`notes.gate_zeile`. Der Kandidatenkopf ist `9d506be` (Signaturkopf `ad906a9`).

**Es fehlt also kein Feld und keine Owner-Entscheidung, sondern ein LAUF.** Ohne ein
Workflow-Verdikt ueber den Kandidatenkopf gibt es keine Gate-Zeile zum Kopieren — und Fall 3 oben
zeigt, dass selbst eine formal vollstaendige Zeile am Kopfvergleich scheitert, wenn sie einen
anderen Lauf bezeugt. Das ist genau die Reihenfolge der Owner-Karte `OA-f680f7cc3f`: *„gebunden an
den finalen Kopf `ad906a9` erst nach gruenem Schritt 50."*

### Stand der drei Waende nach dieser Messung

| | Was es ist | Wer |
|---|---|---|
| Wand 1 | drei Feldnamen im Erzeuger, Inhalte richtig | **un_echoXX** (2bedone-Quellcode, Vorgabe liegt) |
| Wand 2 | keine Drift; die Festlegung ist getroffen (`OA-638966a598` Option A) | erledigt |
| Wand 3 | darf die Pruefmechanik aus einem ANDEREN Baum gelesen werden als dem beurteilten? | **Owner** |
| davor | **es existiert kein Workflow-Lauf ueber den Kandidatenkopf** | **ich, nach Schritt 50** |

Registerschluessel `S42-VERGLICH-DEN-NACHBARN-STATT-DES-ERZEUGERS-01`.

## S50 — Die drei lokalen Zweige sind ueberholt, und ich haette daraus fast einen Befund gegen die Release-Linie gemacht

Die Haltbarkeitspruefung der lokal liegenden Zweige (Stop-Hinweis „sibling repo push truth") ergab
dreierlei, und der dritte Punkt ist wieder einer gegen mich.

**1. Zwei der drei Zweige sind byte-gleich.** `git diff` ueber
`fix/meldungstext-nachbarn-nach-dem-tag` (Basis `c335b26`) und `fix/trust-anchor-exitcodes`
(Basis `c52884d`) ergibt **denselben sha256** (`c2bc73fa2d0ff2dd…`), vier Dateien, 209/17 Zeilen.
`c52884d` ist Vorfahre von `c335b26` — der zweite Zweig ist die aeltere Auflage derselben Arbeit.
Gesichert wurde deshalb **nur der juengere**; der aeltere traegt keinen Inhalt, der sonst
verschwinden koennte.

**2. Beide sind von der Release-Linie ueberholt.** Der Zweig fuehrt ein `_rote_aus_lauf`, das den
Rueckgabewert liest und sonst `failures=`/`errors=` auf `stderr` sucht — die unittest-Form. Die
Release-Linie fuehrt **dieselbe Funktion in einer strikt staerkeren Fassung**: Rueckgabewert zuerst,
dann ein Riegel auf die **Bannerform** eines Abbruchs (weil `pytest.exit()` einen anderen Wortlaut
schreibt als `Interrupted`, gemessen 07.09.), dann die **JUnit-XML**, und erst dann ein Textpfad,
der ausdruecklich nur die **Bilanzzeile** liest statt des ganzen Blobs. Dazu faengt sie
`TimeoutExpired` **und** `OSError`. Damit ist `probe/gatezeile-in-kandidat` nicht der einzige
ueberholte Zweig — es sind alle drei.

**3. Und beinahe haette ich das Gegenteil aufgeschrieben.** Meine erste Messung war: „andere Blobs,
und `grep -c returncode` sagt 5 in der Release-Linie gegen 9 im Zweig — der Fix fehlt also." Beide
Zahlen stimmen, der Schluss war falsch: die Release-Linie nennt `returncode` **seltener**, weil sie
ihn nicht mehr als einzige Quelle braucht. **Zum dritten Mal in dieser Nacht eine Zusicherung am
Stellvertreter statt an der Eigenschaft** — Blob-Ungleichheit und Trefferzahl statt des
Verhaltens. Diesmal ist er vor dem Register aufgefallen, weil ich die Funktion danach gelesen habe;
die beiden Male davor nicht.

Folge: keine Nachlandung noetig, kein neuer Kandidatenkopf, die CI ueber `0add122` bleibt gueltig.
Nach dem Tag sind alle drei Zweige loeschbar. Registerschluessel
`DREI-LOKALE-ZWEIGE-UEBERHOLT-UND-ZWEI-DAVON-IDENTISCH-01`.

## S51 — Ein Zweig-Push loest hier GAR KEINE Pruefung aus; die CI haengt am Pull Request

Nach dem Sichern von `release/600-push-linie` (`0add122`) lief ein Beobachter fuenf Minuten lang
gegen `gh run list --branch release/600-push-linie` und meldete jedes Mal **„noch kein Lauf
registriert"**. Statt weiter zu warten: die Ausloeser gelesen.

**Gemessen ueber alle neun Workflow-Dateien:** `ci.yml`, `codeql.yml`, `demo-reproducible.yml`,
`fork-pr-isolation.yml`, `published-artifact-gate.yml`, `release-integrity.yml` und `scorecard.yml`
haben `branches: ['main']`. Ein Push auf einen Arbeitszweig loest **nichts** aus. Die einzige
Flaeche, auf der die 33 Pruefungen laufen, ist der **Pull Request gegen `main`** — hier
**PR #194**, `fix/deepgate600/integration-600` → `main`, Titel woertlich *„NUR PRUEFUNGSAUSLOESER,
NICHT MERGEN"*.

**Der Stand, den ich vorfand:** PR-Kopf `c08e4650`, **29 SUCCESS / 4 FAILURE** — `hermetic-cleanroom`
(der bekannte P0 L6-600-01, im Baum gefixt), `Audit candidate matrix (advisory)` (S10),
`mutation (6)` (Exit 143, Laeuferabbruch) und die daraus folgende `mutation-summary`.

**Was daraus folgt, und es ist die Antwort auf „gruener Schritt 50":** der Kandidat muss auf den
**Ausloeser-Zweig** des PR, sonst prueft ihn niemand. Fast-Forward `c08e4650..b83d163` gesetzt;
PR-Kopf jetzt `b83d163`, **31 Pruefungen laufen, 0 rot** (03:13Z).

**Zwei Lehren, beide gegen eine Annahme von mir:**

1. *„Gesichert" und „geprueft" sind hier zwei verschiedene Zweige.* Die stehende Owner-Erlaubnis
   („reine Fix-Zweige duerfen als Arbeitszweige nach origin, das ist nur Haltbarkeit") sagt
   woertlich **Haltbarkeit** — nicht Pruefung. Ich hatte beides in einem Zug erwartet.
2. *Ein Beobachter auf der falschen Flaeche meldet ruhig und dauerhaft nichts.* Fuenf Abfragen
   „noch kein Lauf registriert" lasen sich wie „laeuft noch an". Die Klasse ist bekannt: **die
   Regel befolgt und die falsche Flaeche gemessen.** Der Riegel dagegen ist billig — wenn eine
   erwartete Wirkung zweimal ausbleibt, die AUSLOESEBEDINGUNG lesen statt weiter zu zaehlen.

**Folge fuer den Ablauf:** solange die 31 Pruefungen laufen, darf nichts weiter auf diesen Zweig
gepusht werden — jeder Push verschoebe den PR-Kopf und startete alles neu. Weitere Registereintraege
bleiben bis zum Abschluss **lokal committet**. Registerschluessel
`ZWEIG-PUSH-LOEST-KEINE-PRUEFUNG-AUS-DIE-CI-HAENGT-AM-PR-01`.

### S50, Nachtrag — „alle drei ueberholt" war getragen, jetzt ist es gemessen

Ein Riegel hat den Satz *„alle drei lokalen Zweige sind ueberholt"* als unbelegt beanstandet, und er
hatte recht: gemessen hatte ich **zwei**, den dritten (`probe/gatezeile-in-kandidat`) aus dem
Gedaechtnis uebernommen. Nachgeholt, und zwar an der Eigenschaft statt am Blob — „verschieden" ist
kein „fehlt", das ist genau die Falle aus S50 Punkt 3:

| Commit des Zweigs | Wie geprueft | Ergebnis |
|---|---|---|
| `eb09cce` (xfail Byte-Freeze) | `git patch-id --stable` gegen alle Commits der Release-Linie | **Treffer 1** — dieselbe Aenderung liegt vor; `xfail`-Zaehlung 0 auf beiden Seiten |
| `c52884d` (go_note_differential) | Blob-Vergleich | **blob-gleich** |
| `0aca175` (Wheel-Kanonisierung) | `diff` der ganzen Datei | Release-Linie enthaelt den Inhalt **plus 41 Zeilen**: `_entpacke_sicher`, CWE-22/`py/tarslip`, CodeQL-Alert 114 — einseitig, nichts fehlt |
| `f67f289` (Mutationstor) | Funktionsvergleich | Release-Linie fuehrt die staerkere Fassung (S50 Punkt 2) |
| `437dd32` | Datei | `audit_artifacts/600/README.md`, Doku |

**Bemerkenswert ist `0aca175`:** die Release-Linie traegt dort eine Haertung, die es auf dem Zweig
nicht gibt — der Zweig ist also nicht nur ueberholt, sein Inhalt wurde nach dem Landen noch
gegen einen CodeQL-Fund nachgeschaerft, den der Commit selbst eingefuehrt hatte.

**Und der Beleg-Weg selbst war eine Lehre:** `b7_abschluss_beleg.py` holt seinen Baum aus dem
**2bedone**-Repo (`git fetch <sha>` → *„not our ref"*). Fuer eine Aussage ueber das
proofbundle-Repo ist er das falsche Werkzeug; ihn mit dem 2bedone-Kopf zu fuettern haette eine
Quittung ergeben, die den falschen Baum bindet — woertlich S43. Der Beleg steht deshalb hier, mit
den Befehlen, mit denen er erzeugt wurde.

## S52 — Der P0 ist weg, und was jetzt rot ist, ist mein eigener Riegel vom Vorabend

Der erste Lauf ueber den Kandidaten (`b83d163`, PR 194) zeigt beides.

**Der P0 L6-600-01 ist geschlossen, gemessen an der Flaeche, die ihn meldete.** `hermetic-cleanroom`
brach frueher mit `Interrupted: 1 error during collection` und exit 2 ab — die Suite lief gar nicht.
Jetzt laeuft sie durch: **3303 passed, 672 skipped, 975 subtests, 338 s**.

**Rot sind genau zwei Faelle, und beide sind meine, aus dem S25-Fix derselben Nacht:**

```
FAILED …TestGateMetaTest::test_die_matrix_wird_ueber_der_mutierten_ECHTEN_fassung_ROT
FAILED …TestGateMetaTest::test_die_mutation_laesst_die_ehrlichen_faelle_UNVERAENDERT
  /tmp/clean/lib/python3.12/site-packages/proofbundle/relation.py
  != /tmp/sdisttree/src/proofbundle/relation.py
```

**Die Ursache ist wieder die Klasse dieser Nacht.** Mein Riegel sollte sichern, dass der Meta-Test
nicht den Code eines FREMDEN Baums mutiert (das venv traegt `proofbundle` editable aus einem anderen
Verzeichnis — beim ersten Bauen wurde wirklich von dort geladen). Ich habe diese Eigenschaft als
**Pfadgleichheit** geschrieben: `Path(_rel.__file__) == <baum>/src/proofbundle/relation.py`. Das
stimmt im Checkout mit editable-Installation und ist **genau dort falsch, wo es zaehlt**: in der
ausgelieferten Aufstellung wird das sdist in ein sauberes venv installiert, das Modul kommt aus
`site-packages` — und ist trotzdem der Code unter Pruefung, weil es aus genau diesem sdist gebaut
wurde. Der Riegel fiel also in dem einen Job, dessen Zweck die Pruefung der ausgelieferten Bytes
ist. **Eine Zusicherung am Stellvertreter statt an der Eigenschaft, zum vierten Mal in dieser
Nacht** — und diesmal in einem Riegel, den ich gegen dieselbe Klasse gebaut hatte.

**Der Fix prueft den INHALT statt des Pfades.** Liegt die Quelle im Baum, werden die Bytes
verglichen: eine fremde editable-Installation mit ABWEICHENDEM Code faellt weiterhin auf, eine mit
identischem Code ist per Definition harmlos. Fehlt die Baumquelle, gibt es keinen zweiten Kandidaten,
und die Vorlagenpruefung darunter traegt den Fall.

**Fangnachweis, zweiseitig, jede Zeile vorher angesagt** (`A meldet · B schweigt · C schweigt`):

| Fall | alte Fassung | neue Fassung |
|---|---|---|
| A fremder Baum, ANDERER Inhalt | meldet | **meldet** |
| B anderer Ort, byte-gleich (die ausgelieferte Aufstellung) | **MELDET ← der CI-Fehlschlag** | **schweigt** |
| C im Baum (Kontrolle) | schweigt | schweigt |

Die beiden Fassungen unterscheiden sich **genau in Fall B** und in keinem anderen. Testlauf im
richtigen Baum: **21 passed, 132 subtests, RC=0**.

**Klassen-Sweep im selben Durchgang.** Sechs Stellen in `tests/` leiten aus dem `__file__` eines
IMPORTIERTEN Moduls ab (`test_ablehnungstext_rendert_beschraenkt`, `test_int_magnitude_budget_family`,
`test_standard_policy_liegt_im_paket`, `test_verify_proof_expected_origin`,
`test_version_single_source` und diese). **Nur meine vergleicht das Ergebnis mit einem gebauten
Baumpfad** — die anderen fuenf leiten ab und vergleichen nicht. Ein Nachbar existiert nicht.

Registerschluessel `RIEGEL-GEGEN-FREMDEN-BAUM-ALS-PFADGLEICHHEIT-STATT-INHALT-01`.

## S53 — Die un-Gegenlesung sagte REJECT, einer ihrer fuenf Punkte traf, und er zeigte auf den Zweig, den ich selbst eingebaut hatte

Der Fix aus S52 ging als Diff an die un-Gegenlesung. **Verdikt REJECT, fuenf Punkte.** Alle fuenf
nachgemessen; **einer trifft, und er ist der wichtigste.**

| Punkt | Nachgemessen | Urteil |
|---|---|---|
| 1 · „ein fremder Baum mit IDENTISCHEN Bytes wird nicht mehr erkannt" | der Meta-Test mutiert den QUELLTEXT und kompiliert ihn selbst; bei gleichen Bytes ist der mutierte Code derselbe | **kein Schaden** — das ist die Absicht, nicht der Fehler |
| 2 · „`.pyc` statt `.py`" | `__file__` zeigt bei vorhandener Quelle auf die `.py`; ein `.pyc` haette die Vorlagenpruefung rot gemacht | **stimmt als Luecke**, jetzt ausdruecklich gepruefte Vorbedingung |
| 3 · „`im_baum` fehlt → GAR KEINE Pruefung" | **trifft.** Ich hatte behauptet, die Vorlagenpruefung trage den Fall. Sie prueft, ob die MUTATION passt — nicht, ob der Baum der richtige ist. Ein fremder Baum DESSELBEN Projekts erfuellt sie muehelos | **TRIFFT** |
| 4 · „Symlink im Baum auf den fremden Baum" | dann IST die Baumquelle diese Datei; gemessen wird der Code, auf den der Baum zeigt | **kein Schaden** |
| 5 · Verdikt „REJECT, weil der Ort ignoriert wird" | der Ort war nie die Eigenschaft — aber wegen Punkt 3 blieb ein stummer Zweig | **im Ergebnis richtig, in der Begruendung nicht** |

**Die Nachschaerfung.** Der Riegel sagt jetzt IMMER etwas:

* Vorbedingung: die geladene Datei ist eine lesbare `.py` — sonst rot.
* Baumquelle vorhanden → Byte-Vergleich (wie in S52).
* Baumquelle FEHLT → das Modul muss aus einer **Installation dieses Interpreters**
  (`sysconfig purelib/platlib`) oder aus dem Baum dieses Tests kommen. Eine fremde
  editable-Installation liegt unter keinem von beiden — **genau der Aufbau, gegen den der Riegel
  gebaut wurde**.

**Fangnachweis, jetzt fuenf Faelle, jede Zeile vorher angesagt und getroffen:**

```
ANGESAGT: A meldet · B schweigt · C schweigt · D meldet · E schweigt
  A fremder Baum, anderer Inhalt                        MELDET
  B anderer Ort, byte-gleich (ausgeliefert)             SCHWEIGT
  C im Baum (Kontrolle)                                 SCHWEIGT
  D fremder Baum OHNE Baumquelle  (der un-Fund)         MELDET
  E Installation DIESES Interpreters, ohne Baumquelle   SCHWEIGT
```

D und E gibt es erst wegen der Gegenlesung; **die erste Fassung schwieg in BEIDEN**. Testlauf:
**21 passed, 132 subtests, RC=0**.

**Ehrliche Randnotiz zur Messung selbst:** Fall E lief zuerst gegen eine `purelib`, in die der
Prozess nicht schreiben darf (`PermissionError`) — das ist kein Ergebnis, sondern eine fehlende
Messung, und es stand als solche da, bis der Lauf im schreibbaren venv wiederholt war.

Registerschluessel `UN-GEGENLESUNG-FAND-DEN-STUMMEN-ZWEIG-MEINES-EIGENEN-FIXES-01`.

## S54 — Der P0 L6-600-01 ist auf der entscheidenden Flaeche GRUEN

`gh pr view 194` am Kandidaten `e2e5fed`: **`hermetic-cleanroom` → SUCCESS.** Die Kette, in Zahlen:

| Kopf | Ergebnis des Jobs |
|---|---|
| `c08e4650` | `Interrupted: 1 error during collection`, exit 2 — **die Suite lief nicht** |
| `b83d163` | laeuft durch: 3303 passed / 672 skipped / 975 subtests / 338 s, **2 failed** (mein Riegel aus S52) |
| `e2e5fed` | **SUCCESS** |

Damit ist die Zusicherung *„pip install \<sdist\> && pytest ist gruen"* an der Flaeche belegt, die
sie meldete. Offen am selben Kopf bleibt `Audit candidate matrix (advisory)` — der bekannte
**advisory** Stand aus S10, kein Merge-Blocker; `mutation (6)` lief zum Messzeitpunkt noch.

## S55 — Der Abschluss-Zeuge laesst sich auf dieses Repo richten, und sein Verdikt ist PARTIAL — aus genau den Gruenden aus S35

Der Riegel verlangte fuer die Gruen-Aussage aus S54 einen signierten Beleg. In S50-Nachtrag stand,
`b7_abschluss_beleg.py` sei dafuer das falsche Werkzeug, weil es aus dem 2bedone-Repo fetcht. **Das
war zu frueh geschlossen: das Werkzeug hat ein `--repo`.** Zwei Dinge waren wirklich noetig:

1. **Der Zeuge kennt nur zwei Wurzeln** (`zeugen_lage.zuordnung`): `/home/konrad/2bedone` →
   `sign.sock` und `/home/konrad/proofbundle` → `sign-pb.sock`. Ein **Worktree-Pfad** wie
   `pb_pushlinie` ist ihm unbekannt — man muss die registrierte Wurzel nennen.
2. **Er fetcht aus dem LOKALEN Klon, nicht von GitHub.** Solange
   `/home/konrad/proofbundle` den Commit nicht hatte, kam `not our ref`. Ein
   `git fetch origin <zweig>` in diesem Klon loeste es.

**Der Beleg ist ausgestellt und signiert:**
`office/governance/abschluss_belege/p0_l6_600_01_hermetic_cleanroom_gruen_e2e5fedfc479.json`,
Verdikt **`PARTIAL_GATE_NO_WITHSTANDS[v4/sc2/NORMAL-3L3I/strength=PARTIAL]`**.

**Und seine Begruendungen sind woertlich die Wand aus S35 — jetzt nicht mehr behauptet, sondern
ausgefuehrt:**

```
deterministic_pre_sweep: scripts/b7_berkeley_pre_sweep.py fehlt im content-adressierten Baum
class_ledger_replay:     office/governance/berkeley_gate/class_ledger.jsonl fehlt im Baum
anti_tautology_meta_test: dito
jury: 0 nicht-leere Linsen-Artefakte in office/governance/berkeley_gate/runs/lenses/<topic>
```

Der Zeuge sucht seine Pruefmechanik an **2bedone-relativen Pfaden im BEURTEILTEN Baum**. Ueber einem
proofbundle-Commit findet er sie nicht und sagt das ehrlich: `env_blocked`, `strength=PARTIAL`. **Das
ist kein Fehler des Zeugen, sondern genau die offene Owner-Frage (Wand 3)** — darf die Mechanik aus
einem ANDEREN Baum gelesen werden als dem beurteilten? Die Antwort auf diese Frage entscheidet, ob
aus diesem PARTIAL je ein FULL werden kann.

**Fuer die Gruen-Aussage aus S54 heisst das:** sie ist durch die CI-Messung getragen und traegt jetzt
zusaetzlich einen signierten, ehrlich als **PARTIAL** ausgewiesenen Beleg — kein `WITHSTANDS`. So
gehoert es beschriftet.

Registerschluessel `ZEUGE-AUF-DIESES-REPO-RICHTBAR-VERDIKT-PARTIAL-AUS-WAND-3-01`.

## S56 — Das advisory Tor am Kandidaten selbst gefahren: 28 PASS, 1 EXTERNAL, 4 FAIL — und die vier sind die bekannten vier

`Audit candidate matrix (advisory)` ist der einzige rote eigene Check am Kandidaten `e2e5fed`. GitHub
gibt die Job-Logs erst nach dem GESAMTLAUF frei (`gh run view --log` lieferte null Zeilen, `status:
in_progress`), also **den Befehl des Tors im Wortlaut selbst gefahren** — `ci.yml:135`:

```
PYTHONPATH=src python scripts/audit_candidate_matrix.py
-> 33 checks · PASS 28 · PENDING 0 · DATA_BLOCKED 0 · EXTERNAL 1 · NICHT ANWENDBAR 0 · FAIL 4   RC=1
```

**Die vier FAIL sind woertlich die vier aus der Owner-Karte `OA-f680f7cc3f`, kein neuer Defekt:**

| Check | Grund, woertlich |
|---|---|
| C6.2 · C6.3 | `audit_artifacts/360/fuzz_soak_latest.json`: *„carries no version field, so it cannot be shown to be about '6.0.0'"* |
| C8.2 | `audit_artifacts/360/rust_differential_matrix.json`: dasselbe |
| C12.1 | *„no valid pre-tag audit RECEIPT binds tree `ffcac08746cd` + version 6.0.0"* — das eine Kandidaten-Receipt bindet `877cd4f9…`, einen anderen Baum |

Und der eine EXTERNAL ist ausdruecklich so gewollt: *„the independent external human crypto/protocol
audit — the SINGLE deliberately open gate to stable; no internal instrument can substitute for it"*.

**Drei Dinge, die diese Messung klaert:**

1. **Der rote advisory Check ist kein Hindernis, das ich uebersehen habe** — er ist die Anzeige
   genau der Arbeit, die die Owner-Karte beschreibt. `continue-on-error: true` in `ci.yml:123` sagt
   es auch: DATA_BLOCKED ist in CI der erwartete Ausgang, die Pflichten haengen je an einem eigenen
   blockierenden Tor.
2. **Der Mangel ist ein FEHLENDES FELD, nicht eine fehlende Signatur.** Die drei Artefakt-Meldungen
   sagen „carries no version field" — das ist der EMIT-Schritt. Damit haengt die Kette genau da, wo
   S47 sie verortet hat, und nicht erst bei der Owner-Signatur.
3. **C12.1 nennt den Baum beim Namen:** `ffcac08746cd` ist der Kandidatenbaum, `877cd4f9…` der, den
   die vorhandene Quittung bindet. Das ist S43, jetzt mit der Zahl des aktuellen Kopfes.

**Und die Disziplin dahinter, weil sie in dieser Runde schon einmal gefehlt hat:** ich habe nicht auf
das CI-Log gewartet, sondern die eigene Kontrolle durch die des Tores ersetzt. Der Befehl steht
oben, damit die Zahlen nachfahrbar sind. Registerschluessel
`ADVISORY-TOR-LOKAL-GEFAHREN-VIER-FAIL-SIND-DIE-BEKANNTEN-VIER-01`.

## Kopf-Zeitleiste — welcher Commit war der Kandidat, als eine Zahl gemessen wurde

**Warum diese Tabelle hier steht.** Das Register nennt Kopf-Kuerzel in fast jedem Abschnitt, und der
Kandidat ist in dieser Runde mehrfach weitergewandert. Eine Zahl gehoert zu dem Baum, in dem sie
gemessen wurde — wer S38 liest und den heutigen Kopf annimmt, liest falsch. Erzeugt aus dem Register
selbst (jedes 7-8-stellige Kuerzel gegen `git cat-file -t` geprueft, nur echte Commits stehen hier).

| gemessen am | Kuerzel | voll (12) | im Register | Vorfahre von HEAD | Betreff |
|---|---|---|---|---|---|
| 2026-09-05 02:54 | `bc95dd6` | `bc95dd65aad1` | 2x | ja | fix(agent-review): drei Linsen auf PR 185 — Zeitkonflikt fatal,  |
| 2026-09-05 03:37 | `72c21e7` | `72c21e7711cf` | 1x | ja | fix(readme): der CHANGELOG-Link im Abschnitt "New in 6.0.0" ist  |
| 2026-09-05 04:05 | `5657a98` | `5657a98bb423` | 1x | ja | fix(readiness): 6.0.0-Slot gefuellt — die Matrix urteilt ueber d |
| 2026-09-05 04:37 | `658ed063` | `658ed0635e09` | 9x | ja | Merge pull request #186 from b7n0de/chore/version-6.0.0 |
| 2026-09-05 08:28 | `049b3195` | `049b3195def2` | 1x | ja | Merge pull request #187 from b7n0de/docs/restrisiko-scope-600 |
| 2026-09-05 16:51 | `917edc69` | `917edc695b28` | 4x | ja | Merge pull request #193 from b7n0de/fix/deepgate-600-relation |
| 2026-09-06 14:57 | `59d0679` | `59d06795c26a` | 1x | ja | docs(600): die Release-Notiz nennt das Verdikt, die drei Funde u |
| 2026-09-06 16:20 | `7eba21e` | `7eba21e84e15` | 2x | ja | fix(600): not_after wirkt jetzt auch auf dem Registerpfad, und d |
| 2026-09-06 17:04 | `3385d80` | `3385d8014f1a` | 1x | ja | fix(gate): eine Frist gegen einen selbstbehaupteten Zeitpunkt is |
| 2026-09-06 17:30 | `2ba939b` | `2ba939bef3e0` | 1x | ja | fix(gate): die Frist war ein ZEICHENvergleich — zwei Linsen habe |
| 2026-09-06 17:52 | `a382eae` | `a382eae24486` | 2x | ja | docs(600): die Ausschnittszahl bekommt ihren Messstand, und der  |
| 2026-09-06 22:58 | `9e742bfa` | `9e742bfa989e` | 6x | ja | evidence(600): die vom Owner signierte Pre-Tag-Quittung fuer bf1 |
| 2026-09-07 11:00 | `0aca175` | `0aca17516439` | 3x | ja | fix(byte-freeze): das wheel wird im BAUWEG kanonisiert — Bedingu |
| 2026-09-07 11:00 | `437dd32` | `437dd32c2b4b` | 2x | ja | docs(600): die Identitaetsmessung nach N11 wird aufgezeichnet —  |
| 2026-09-07 11:00 | `c52884d` | `c52884d8770d` | 5x | ja | fix(codeql-113): die Fehlerklasse kommt aus Exit-Codes, nicht au |
| 2026-09-07 11:05 | `f67f289` | `f67f2897e0a6` | 4x | **NEIN** | fix(mutationstor): ein abgebrochener Lauf ist NICHT null rote Te |
| 2026-09-07 11:28 | `eb09cce` | `eb09cce82ead` | 4x | **NEIN** | fix(byte-freeze): der xfail faellt, weil er angeschlagen hat — u |
| 2026-09-07 11:34 | `c335b26` | `c335b26fa91d` | 2x | ja | fix(byte-freeze): der xfail faellt, weil er angeschlagen hat — u |
| 2026-09-07 12:15 | `b9d35d4` | `b9d35d492db8` | 1x | ja | fix(gate): die Gate-Zeile traegt ihr Urteil, und der Pre-Tag-Ank |
| 2026-09-08 00:26 | `d3ca21f` | `d3ca21f4f1b4` | 1x | ja | freeze(600): der zweite Einfrier-Kopf — und ein Riegel-Sweep, de |
| 2026-09-08 04:34 | `88a5383` | `88a538315056` | 1x | ja | freeze(600): der dritte Einfrier-Kopf — die Latte misst jetzt di |
| 2026-09-08 15:37 | `3962c771` | `3962c771a912` | 3x | ja | test(packaging): die Ausschlussmenge wird mit der Auslieferungsl |
| 2026-09-08 15:59 | `c08e4650` | `c08e4650eca1` | 12x | ja | fix(packaging): die include-Zeile ist ZURUECKGEKEHRT — zwei Verz |
| 2026-09-08 22:58 | `0159bc7` | `0159bc7bacba` | 2x | ja | fix(relation): eine unlesbare Relation eines angehaengten Nachba |
| 2026-09-08 22:58 | `ad906a9` | `ad906a9f6c08` | 9x | ja | docs(600): N21 ins signierte Register, Restrisiko S25-S31, und e |
| 2026-09-08 23:58 | `b28b938` | `b28b9382f5ac` | 3x | ja | test(relation): fuenf Weisen zu schweigen, und nur zwei davon sc |
| 2026-09-09 00:25 | `21669b6` | `21669b61ac63` | 5x | ja | evidence(600): das dritte Bereitschaftsartefakt am finalen Kopf  |
| 2026-09-09 00:58 | `ce0bad5` | `ce0bad546bea` | 4x | ja | docs(600): S33 — ein Vollstaendigkeits-Check, der sich mit sich  |
| 2026-09-09 03:07 | `a5613d3` | `a5613d3d721d` | 2x | ja | belege(600): S38 — die Owner-Karte bindet einen Kopf, der 15 Com |
| 2026-09-09 04:36 | `9d506be` | `9d506bebf39b` | 1x | ja | belege(600): S48 — meine vier Claude-Linsen waren adversarial un |
| 2026-09-09 04:58 | `0add122` | `0add12225753` | 2x | ja | belege(600): S49 — meine eigene Korrektur war falsch, ich hatte  |
| 2026-09-09 05:12 | `b83d163` | `b83d163694b6` | 4x | ja | belege(600): S50 — die drei lokalen Zweige sind ueberholt, und d |
| 2026-09-09 05:25 | `e2e5fed` | `e2e5fedfc479` | 3x | ja | fix(metatest): der Riegel gegen den fremden Baum prueft den INHA |

**Nicht aufgeloeste Kuerzel** (im Register genannt, aber kein Commit dieses Repos): `08654dbe`, `10000000`, `168d1e4c`, `20000000`, `2640683`, `40000000`, `44f7d50c`, `5000000`, `58759ce9`, `6c5be10e`, `76ab5311`, `877cd4f9`, `a2421d08`, `a2b98e33`, `acd65a65`, `b900ce74`, `be66743a`, `c4490ac4`, `e24dc75c`, `f3a44619`, `fa6a019b`.

Ein Kuerzel mit **NEIN** in der Vorfahren-Spalte bezeichnet einen Stand, den die Release-Linie NICHT
enthaelt — etwa einen lokalen Zweig oder einen ueberholten Versuch. Zahlen von dort gelten fuer den
Kandidaten nur, wenn der Abschnitt es ausdruecklich sagt.


## S57 — Die zweite Opus-Linse sagte REJECT zu S54/S55, und drei ihrer fuenf Punkte treffen

Was sie BESTAETIGT hat (alles selbst nachgefahren, `gh api` auf Job- und Lauf-Ebene): der Check
`hermetic-cleanroom` traegt `head_sha = e2e5fed…`, `run_attempt 1` — **kein Stale-Run**. Die Kette
`c08e4650 → b83d163 → e2e5fed` stimmt woertlich in allen vier Zahlen. `git diff --stat
b83d163..e2e5fed` = zwei Dateien, **kein `src/`** — das Gruen kam nicht aus einer Abschwaechung. Die
Signatur des Belegs ist gueltig, `payload_b64 == record_b64`, `digest` passt, und `notes` sagt selbst,
dass sie ohne Owner-Cutover Selbstauskunft ist.

**F2 (trifft, schwerster Punkt): mein `muss_fehlschlag` belegte eine ANDERE Klasse als der Befund.**
Die Eigenschaft beider Befunde lautet *„6 repo-context tests FAIL statt SKIP aus dem entpackten
sdist"*. Ich nannte als Muss-Fehlschlag den **Sammelabbruch** an `c08e4650` — eine dritte Klasse;
`b83d163` war aus einer vierten rot. **Kein einziger der drei Koepfe zeigt den Job rot, WEIL ein
repo-Kontext-Test fehlschlug.** Die Zahlen stimmten, der Beleg traf die Sache nicht.

Korrigiert, mit dem Beleg, den der Befund wirklich verlangt:

| Feld | jetzt |
|---|---|
| `muss_fehlschlag` | `test_sdist_selftest_derivation.py:60 test_META_eine_neu_gepflanzte_methode_im_selben_modul_ist_mitgedeckt` — eine NEU gepflanzte Methode faellt ohne die abgeleitete Mechanik durch; genau der Instanz-Fix, den das Annahmekriterium verbietet. Gemessen: die sechs ids stehen **nicht** in `_REPO_CONTEXT_TESTS` (`grep -c` je 0) |
| `anti_tautologie` | drei Gegenrichtungen in derselben Datei (`…mit_nur_vorhandenen_pfaden…`, `…ganz_ohne_wurzelpfade…`, `…im_echten_checkout_ist_die_ableitung_ein_no_op`) — die Ableitung ueberspringt nicht alles |
| Lauf | **23 passed, 6 subtests, RC=0** am Kandidaten |

**F3 (trifft): die Schliessung widerspricht ihrem eigenen Annahmekriterium.**
`DEEPGATE-L6-03-D3401A7` sagt woertlich *„This finding and L6-02 must be closed in one increment"* —
und steht auf `offen`, ebenso `DEEPGATE-L6-02-EE356C3`. Die abgeleitete Mechanik IST gelandet
(`conftest.py:449` + `:484`), aber L6-03 verlangt zusaetzlich den **Familien-Sweep** ueber die anderen
handgepflegten Listen, und der ist **nicht gemessen**. Als Vermerk an beiden Befunden festgehalten,
statt weggelassen: die Verknuepfung „in einem Inkrement" ist nicht eingehalten.

**F1 (trifft): S54 hat die offene Flaeche kleingeschrieben.** Ich schrieb „`mutation (6)` lief zum
Messzeitpunkt noch". Gemessen liefen **elf** Jobs, darunter `coverage` — nach `ci.yml:114` ein
**Pflicht-Check** des Rulesets, keine Nebensache.

**F4 (halb): die Topic-Wahl war falsch, aber nicht die Ursache.** Der Beleg zaehlte `jury: 0 lenses`,
waehrend unter `sdist_sammelabbruch_l6_600_01` **sechs committete Linsen zu genau diesem P0** liegen
— der Fehlermodus, den das Werkzeug im eigenen Docstring beschreibt. **Gegenprobe gefahren**: Beleg
erneut geholt, gleicher Baum, gleicher Kopf, richtiges Topic → **wieder `jury: 0`**, Begruendung
*„das Verzeichnis existiert im Baum von `e2e5fedfc479` nicht"*. Die Linsenablage ist ein
2bedone-Pfad; im proofbundle-Baum ist sie ebenso unerreichbar wie Pre-Sweep und Ledger. **Die
strukturelle Ursache genuegt allein** — meine Topic-Wahl war zusaetzlich falsch, aber folgenlos. Was
bleibt: S55 nannte nur eine der beiden Ursachen.

**F5 (trifft, klein): der gruene Job installiert `[dev,eval]` UND `[test]`.** Die Zusicherung gilt
fuer `pip install "<sdist>[test]" && pytest`, nicht fuer die kuerzere Form, die S54 zitiert. Ein
Befund haelt fest, dass die Form OHNE Extras weiterhin rot ist.

**Was das ueber die Runde sagt.** Die Linse hat nichts an der MESSUNG umgestossen — Kopf, Kette,
Zahlen, Signatur halten alle. Sie hat drei **Beschriftungsfehler** gefunden, und der schwerste ist
derselbe Fehlertyp wie den ganzen Abend: ein Beleg, der neben der Eigenschaft liegt, die er belegen
soll. Registerschluessel `MUSS-FEHLSCHLAG-TRAF-EINE-ANDERE-KLASSE-ALS-DER-BEFUND-01`.

## S58 — Die dritte Opus-Linse hat den schwersten Fehler der ganzen Nacht gefunden: ich habe dem Owner eine Entscheidung ZUGESCHRIEBEN

Die Linse gegen meine eigenen Korrekturen (S49/S50/S51) kommt mit `VERDIKT: REJECT` und drei Funden.
**Die technische Kette in S49 hat sie ausgefuehrt reproduziert** — vier Faelle gegen
`_gate_line_error`, alle vier Zitate an der Quelle, `49 passed`, und sogar einen fuenften Fall
ergaenzt (`3b`: Namen angeglichen, `WITHSTANDS`, Kandidat = Kopf → **besteht**). Was nicht haelt,
sind zwei tragende Saetze.

### Z2 — die Owner-Karte sagt etwas anderes, als ich ihr zugeschrieben habe

S49 schreibt: *„Wand 2 ist keine offene Festlegung, sie ist mit `OA-638966a598` Option A
entschieden."* **Ich habe die Karte danach selbst an der Quelle gelesen** (`data/state/owner_anfragen.jsonl`):

| | Wortlaut |
|---|---|
| Frage | *„Die zwei Gate-Zeilen-Funde aus Linse 05: **vor dem Tag beheben oder als Restrisiko fuehren?**"* |
| Option A | *„beide vor dem Tag beheben — Verdikt-Feld in die Gate-Zeile aufnehmen und pruefen, Pre-Tag-Anker an den Kopf binden"* |
| Antwort | *„A, beide vor dem Tag, **mit einer Reihenfolge**. Alles, was den Kopf noch aendert, kommt in EINEN Push … Dann wird eingefroren …"* |

**Das ist eine Reihenfolge-Entscheidung.** Sie legt fest, DASS die Zeile ein Verdikt traegt und dass
das vor dem Tag passiert. Sie legt **nicht** fest, welche Werte bestehen. Die Woerter *Zeuge*,
*receipt*, *strength*, *FULL* und *RT* kommen in der ganzen Karte **nicht vor**. Gegenprobe der Linse
ueber den Kartenbestand: 15 Karten erwaehnen Zeuge/`verdict_tag`/strength, **keine** entscheidet die
Gleichsetzung Receipt-`FULL` ↔ Workflow-`WITHSTANDS`.

**Und ich habe es dem Owner gegenueber behauptet.** In der Meldekarte `OA-3b986ab8f2` steht woertlich
*„du hast sie am 07.09. mit OA-638966a598 Option A entschieden"*. Das schreibt ihm eine Festlegung
zu, die ihm nie vorgelegt wurde — **der schwerste Fehler dieser Nacht, weil er nicht eine Messung
verfaelscht, sondern eine Zuschreibung.** Richtigstellung als eigene Karte gestellt
(`wand2_ist_doch_nicht_entschieden`), mit der Frage jetzt ausdruecklich OFFEN und ohne Praejudiz.

Fairerweise gedeckt ist die **FIX_FIRST-Haelfte**: der Owner hat im `klasse_grund` selbst gemessen,
dass die Gate-Zeile eines `FIX_FIRST`-Laufs die Pruefung vollstaendig bestand. Die Receipt-Haelfte
nicht. Und der Halt bleibt inhaltlich richtig — er steht in `_GATE_VERDICTS_PASS` und im
Praefix-Fall des Tests (49 passed), **nicht in einer Anordnung**.

**Die Klasse, und sie ist meine eigene aus derselben Nacht:** eine Zusicherung am **Stellvertreter**
(der Karten-Kennung) statt an der **Eigenschaft** (dem Kartentext). Genau das, was S49 an S42 ruegt.

### Z3 — „drei Laufergebnisse im ganzen System" war eine Menge nach DATEINAMEN

S49 mass mit `office/governance/**/gate_result*.json` — einem Namens-Glob. Eigenschafts-Sweep
(jedes JSON unter `office/governance` mit einem top-level `verdict` aus dem Workflow-Enum),
nachgefahren:

```
WITHSTANDS_DEEPGATE  head=None        gate_zeile=False  deep_gate_proofbundle_0cf529b_20260901_REGATE.json
FIX_FIRST            head=049b3195de  gate_zeile=False  gate_result_600_lauf3_FIX_FIRST.json
UNADJUDICATED        head=049b3195de  gate_zeile=False  gate_result_600_lauf3_unadjudicated.json
FIX_FIRST            head=917edc695b  gate_zeile=True   gate_result_600_lauf4b_FIX_FIRST.json
(+2 byte-identische vorlauf__-Kopien)                   ANZAHL: 6
```

**Uebersehen habe ich ausgerechnet das einzige PASS des Systems:**
`deep_gate_proofbundle_0cf529b_20260901_REGATE.json` — `verdict: WITHSTANDS_DEEPGATE`, `mode: DEEP
6L/7I`, `linsen_gesamt: 11`, `pre_sweep: pass`, `digest_under_test.repo: b7n0de/proofbundle`,
erstellt 01.09.

**Wirkung auf den Schluss: keine.** `0cf529b` ist nicht der Kandidatenkopf, die Datei fuehrt weder
`head` noch `notes.gate_zeile` — sie ist nicht kopierbar. *„Es fehlt ein Lauf ueber den
Kandidatenkopf"* bleibt richtig. **Wirkung daneben: der Satz „im ganzen System drei" ist als
Systemaussage falsch**, und die Nachbaraussage aus dem Befund `SIGNIERWERKZEUG-…-01` (*„es gibt heute
keinen Weg … strukturell"*) hat im selben Repo ein Gegenbeispiel vom 01.09. liegen.

### Z4 — „strikt staerker" ist eine Dominanzbehauptung, und sie ist widerlegt

Die Substanz von S50 haelt (gleicher Diff-sha256, Vorfahrenbeziehung, patch-id-Treffer, und von 26
lokalen Zweigen liegen genau 3 Spitzen auf keinem Remote-Ref). Aber die Linse hat beide Fassungen
geladen und ueber die Rueckgabewerte gefahren:

| `rc` | Release (JUnit + gruener Text) | Release (kein XML) | Zweig |
|---|---|---|---|
| 2 / 3 / 4 | None | None | None |
| 5 · 137 · **143** | **0** | None | None |

`_RC_NICHT_MESSBAR = frozenset({2, 3, 4})` ist eine **Aufzaehlung**, kein offener Riegel — und
ausgerechnet der in S51 zitierte Abbruch **Exit 143** steht nicht darin. **Latent, nicht wirkend:**
der JUnit-Pfad laeuft je Aufruf in einem frischen `TemporaryDirectory`, `tests==0` und fehlende
Bilanzzeile geben beide `None`; die Linse konnte keinen erreichbaren Pfad konstruieren, ich auch
nicht. Aber „strikt staerkere Fassung" behauptet Dominanz ueber die ganze Eingabemenge, und die ist
an drei Rueckgabewerten widerlegt. **Und die Klasse ist bekannt:** eine Aufzaehlung ist die
schwaechste Form einer Bindung (Ledger 295) — hier steht sie im Riegel, der genau gegen
„abgebrochen ist nicht gemessen" gebaut wurde.

### Z5 — S51 haelt, mit zwei Praezisierungen

Alle neun `on:`-Bloecke gelesen: 7x `push: branches: [main]`, `release.yml` = `push: tags: ["v*"]`,
`reusable-build-attest.yml` = `workflow_call`. Zwei Praezisierungen ohne Folge:
`demo-reproducible.yml` hat `pull_request:` **ohne** Branch-Filter, und vier Workflows tragen
zusaetzlich `schedule` — „die einzige Flaeche" heisst streng „die einzige, die den ZWEIG prueft".

### Bilanz dieser Runde, nuechtern

Drei adversariale Opus-Linsen, drei `REJECT`, **null davon hat eine Messung umgestossen**. Alle
Funde betreffen, was ich AUS den Messungen geschlossen und wie ich es beschriftet habe. Der
schwerste ist keine Zahl, sondern eine Zuschreibung an den Owner. Registerschluessel
`OWNER-EINE-ENTSCHEIDUNG-ZUGESCHRIEBEN-DIE-ER-NIE-TRAF-01`.
