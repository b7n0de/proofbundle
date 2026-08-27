# Pre-tag adversarial deep-gate — run record, iterations 5 to 8 — release 5.0.0

> **The file name says 5_7 and the content now covers 5 to 8.** Renaming it would break the links
> already written into the pre-registrations and the finding queue; the heading is the truth and the
> name is continuity. Iteration 8 is the last section.

This record continues [DEEP_RUN_RECORD_500.md](DEEP_RUN_RECORD_500.md), which documents iterations
1 to 4 and binds its `WITHSTANDS_DEEPGATE` to `9bc179e`. It covers the **four** iterations that ran
after that verdict, under
[PRE_REGISTRATION_DEEP_500_ITER6.md](PRE_REGISTRATION_DEEP_500_ITER6.md),
[PRE_REGISTRATION_DEEP_500_ITER7.md](PRE_REGISTRATION_DEEP_500_ITER7.md) and
[PRE_REGISTRATION_DEEP_500_ITER8.md](PRE_REGISTRATION_DEEP_500_ITER8.md).

**It carries no attestation line and grants no tag.** The line
`pre-tag-adversarial-audit: RUN | version=5.0.0` in the earlier record attests the iteration-4 run
on `9bc179e` and nothing else. Iterations 6, 7 and 8 each returned **`FIX_FIRST`**, and iteration 8
additionally **falsified the standing target RT-04**, which the pre-registrations hold to be not
removable.

**The block below states iteration 7's numbers**; iteration 8 has its own block in the last
section. Reading the two as one would merge a one-finding round with an eight-finding one.

```
verdict          FIX_FIRST
graded commit    d8ec90125ee0ebeecabd676c17c18947a1697d3f
graded src tree  5fc2310b9697879b813f03cc59e8708fb79d8255
mode             [DEEP-GATE: DEEP 6L/7I]
agents           57 · 6 lenses · 16 candidates · 1 survived 3-juror refute-to-kill
RT-01..RT-04     all four attacked, all four confirmed fail-closed
```

## The anti-parity oracle, named with its digest

*(Owner decision `OA-303cb485e8`, 2026-08-26: write the digest out in the run record. The
iteration-7 pre-registration named the commit but not the tree; that half-fulfilled requirement is
closed here rather than by editing a frozen document mid-run.)*

```
oracle commit    89d4fb90ca395f59843aa840910dbb7c4cda635a   (= tag v4.0.0)
oracle src tree  8c124b527ede58fa6333a09d38704588095b976d
measured         git rev-parse 89d4fb9 · 89d4fb9:src · v4.0.0^{commit} · v4.0.0:src
                 commit and tag identical, src trees identical
driven           over PYTHONPATH, no installation — one interpreter reports 4.0.0 or 5.0.0
                 depending only on the path, verified in the freezing round
```

Nothing was unverifiable without it — a git commit determines its tree. What was missing was the
written-out naming, and the requirement asked for that.

---

## Iteration 5 — RECONSTRUCTED from the commit record; no artifact exists

**Source: `git log` alone.** `audit_artifacts/` contains nothing for iteration 5. What follows is
quoted commit prose, not a measurement of this round, and it is marked so because a record that
cannot tell evidence from recollection is worth less than one that admits the difference.

```
graded head (per 66e72f4)   529cd20
finding                     F-C — ASYMMETRIC BINDING
verdict                     not recorded; inferable as FIX_FIRST from the follow-up commit
```

**The finding (`529cd20`):** three of four adapters bound the harness version under
`harness_version`; promptfoo bound it under `promptfoo_version` only, and the lm_eval adapter's own
comment cited promptfoo as an adapter that "binds" — mistaking a different field *name* for the
same binding. A reader comparing receipts across adapters could not tell *"promptfoo reports no
version"* from *"this adapter names it differently."*

**What iteration 5 also proposed, and what was REFUSED:** writing the field unconditionally, since
an absent field cannot be distinguished from *"this adapter does not bind the version."* Refused
because `test_missing_version_field_stays_absent_not_invented` is the stronger argument: writing a
value the harness never reported puts it into EVIDENCE, which is what this project exists against.

**How iteration 5 was closed, and why that is the origin of the feature stop:** with a `feat`
(`66e72f4`). A fix that adds public surface enlarges the graded object; the two jury rounds on it
moved the object again. The Owner cut of 2026-08-26 follows directly from this.

### Jury round on `66e72f4` — RECONSTRUCTED (source: `df2b353`)

* **Finding 1 HELD, the serious one.** `version_status_issues` matched *every* provenance key
  ending in `_status`, so an unrelated `run_status` or `scorer_status` produced a FALSE finding.
  A verifier that invents a finding on a field it was never asked about is worse than one that
  misses something — it makes a valid receipt look non-conformant.
* **Finding 2 DID NOT HOLD.** The jury demanded that a provenance with no status be rejected. It
  must not be: the change is additive *by requirement*, and a status obligation would invalidate
  every receipt issued before 5.0.0. Nailed down by test and conformance vector.
* **Two more came from the author attacking the code afterwards:** a non-dict provenance RAISED
  instead of reporting; `sorted()` over mixed key types raised.

### Jury round 2 on `df2b353` — RECONSTRUCTED (source: `6065815`)

* **Finding 1 HELD and overturned the author's own reasoning.** The suffix rule accepted any
  `<field>_status` whose field ended in `_version`. `schema_version` ends so and is not a
  harness-reported field. Result: `REPORTED_VERSION_FIELDS` as a named set shared by writer and
  verifier, so the two cannot drift into different ideas of the class.
* **Finding 2 HELD.** Called twice, the writer left the version field beside a `not_reported`
  status — a writer producing a block its own verifier rejects is itself the defect.
* **Finding 3 DID NOT HOLD, for the second time:** the same status obligation.

---

## Iteration 6 — MEASURED; stopped before the jury

```
graded commit     6065815   src tree ae07ab3e
pre-registration  PRE_REGISTRATION_DEEP_500_ITER6.md, 16118 B,
                  sha256 9b7386070c56c6b05d74be879ee61374eba0171baa9f471cc6a10db644148cc1,
                  frozen 2026-08-26T09:01:45Z
verdict           FIX_FIRST — the deterministic pre-sweep was not green (runbook step 4)
```

Stopped before the jury deliberately: a jury on a tree about to change is stale before its record
is written. That had already happened twice in this release — iteration 4 bound `9bc179e` with the
head nine commits further, and iteration 5 graded `529cd20` and was overtaken.

```
ledger replay   pass — 161 tests, 156 nodes, 80 of 141 classes (0.5674), 0 regressed,
                0 unusable evidence fields; 5 classes UNEXPLAINED
                convergence estimator DATA_BLOCKED (no lens-by-finding incidence)
full suite      2262 passed, 123 skipped, 555 subtests, 0 failed (minimal lane)
E7  HOLDS       4.0.0 signs passed=true on an all-red run; 5.0.0 emits nothing. With the
                variable set the receipts differ in exactly four fields — and a
                5.0.0-against-5.0.0 control differs in the SAME four (per-run nonces)
E8  HOLDS       payload tampered and re-signed with a fresh key: rc=0 unpinned, rc=1 pinned;
                green control; rotation behaves as a union; without the flag identical to
                4.0.0 except `age` (elapsed time)
E9  SPLIT       lm-eval half holds; capture half REFUTED (below)
E10 HOLDS       eleven probes, including a genuinely 4.0.0-produced provenance that the
                5.0.0 verifier passes unchanged
E11 HOLDS       anti-parity confirms the asymmetry in 4.0.0 and its closure here
```

### Four findings, none P0/P1

| id | severity | outcome |
|---|---|---|
| `CAPTURE-MECHANISM-NIMMT-JEDEN-STRING-…-01` | P3 | **deferred to 5.1.0** (Owner) — refutes E9 |
| `KOMMENTAR-NEBEN-DER-ZEILE-LEHRT-DIE-VERWORFENE-SUFFIX-REGEL-01` | P3 | closed in `d8ec901` |
| `STATUSKLASSE-UEBER-VIER-ADAPTER-EIN-TEST-FAEHRT-EINEN-ERZEUGERPFAD-01` | P3 | closed in `d8ec901` |
| `RUFF-CHECK-IST-AUF-DEM-RELEASE-KANDIDATEN-ROT-…-01` | P2 | closed in `d8ec901` |

The fourth came not from a lens but from the test bench itself: `ruff check .` exited 1 on the
**unmodified** `6065815` (F841 from `bed147b`, i.e. from the ungraded delta), and
`.github/workflows/ci.yml:81` runs it in the `Lint` step **without** `continue-on-error`. The
preparation PR would have gone red on a binding job. Measured against a clean `git archive` export
so the attribution does not rest on the author's own edit.

### The deferred finding, and how the pre-registration bound it in advance

`capture_mechanism` accepts any string into signed evidence — `'live_hook_trust_me'`, `''`,
`'lifecycle_hook '` (trailing space), `'None'`. The three named values live only in a docstring,
while one function over `bind_reported_version` enforces its named set at the writer and raises on
a typo. Same invariant, unswept.

Deferred to 5.1.0 by Owner decision: `capture` is a call parameter of a **public** adapter
function, and fencing it changes acceptance behaviour on a public surface. Measured, nothing in
`src/` reads the value (three non-comment occurrences, all write-side); two tests do read it, so it
is asserted but not enforced.

The iteration-7 pre-registration fixed the consequence **before the run**: a refutation of E9 at
exactly this instance is expected and does **not** withhold the verdict; **any other** refutation
of E9 does; and E9 was reproduced word-for-word rather than narrowed so the refutation would fall
out. It is carried here as an open P3, the way the iteration-4 record carried its non-surviving
register candidate.

### Plant-and-must-catch for the test fix (three runs per probe)

| probe | planted defect | result |
|---|---|---|
| M1 | promptfoo writes a constant placeholder instead of the reported value | 1 failed, 30 passed |
| M2 | `eee` binds no status at all (fallback to the 4.0.0 shape) | 2 failed, 29 passed |
| M3 | `inspect_ai` patches only `harness_version`, `task_version` drops out | 2 failed, 29 passed |

Control green before (31 passed), restore **byte-identical** for all three files, third run after
the restore green again — the effect checked, not only the bytes. Restore via `cp`, not
`git checkout --`: the tree held uncommitted work, and `git checkout` restores from the commit
rather than from the state before. **M1 was caught by exactly ONE test** — not a weak mutant, but
the evidence that `test_promptfoo_reports_none_and_says_so_on_both` is not replaceable.

---

## Iteration 7 — MEASURED; the full jury ran

```
graded commit     d8ec901   src tree 5fc2310b
pre-registration  PRE_REGISTRATION_DEEP_500_ITER7.md, 17149 B,
                  sha256 18991e9ac0b67e2c4f54ca0bc4f9b5f0275c36dce52d62c3135c7dba7c531fd7,
                  frozen 2026-08-26T10:36:43Z
pre-sweep         ledger replay pass (161 tests, 80/141, 0 regressed) ·
                  full suite 2269 passed, 123 skipped, 0 failed · ruff check . exit 0
verdict           FIX_FIRST — 1 confirmed finding
```

E1–E11 were reproduced verbatim; E12 was added because iteration 6's own fix had become part of the
graded tree. **E12 holds structurally:** the `src` diff `6065815..d8ec901` contains **0
non-comment lines**, so no behaviour can differ — and E7, E8, E10 and E11 were re-run on the new
head and reproduced identically.

### The one confirmed finding — `L3-500-DSSEB64-02` (P2)

`src/proofbundle/dsse.py:36-42`. The first arm is strict; the **fallback calls
`urlsafe_b64decode` without `validate=True`**, and Python's default silently discards characters
outside the alphabet. The docstring claims the opposite ("raises binascii.Error if neither is
valid").

Independently re-measured for this record, with a green control:

```
unmodified                verify=True          (control)
payload + '!'             verify=True          envelope bytes DIFFER
payload + newline         verify=True
payload + space           verify=True
payload + tab             verify=True
payload + NUL             verify=True
payload + 'é'             BundleFormatError    correctly rejected — not everything passes
sig     + '!'             verify=True          the signature field itself
sig     + newline         verify=True
```

Call sites `:111` (payload) and `:153` (`signatures[].sig`); the same chokepoint is shared by
`outcome`, `relation_statement`, `verification_summary`, `run_ledger`, `trust_pack`, `intoto` and
`svr`. Measured **27 lax against 51 strict** decode sites.

**BOUND, so this is not read stronger than it is:** this is **not** a signature forgery and **not**
a subject-binding or lineage bypass — `body_sha256` and `derive_subject_digest` are byte-identical
across every accepted variant. What breaks is canonical wire-form identity (dedup, replay
detection, transparency-log leaf identity) and agreement with the project's **own shipped Rust
verifier**, which rejects the identical file. RFC 4648 §3.3 requires a conforming decoder to reject
characters outside the alphabet.

### Ledger coverage — and why the gap is load-bearing this time

The replay covered 80 of 141 classes (0.5674) and returned pass with zero regressions. **61 classes
were not replayed**, and the gate makes no statement about them. That gap is not academic here: the
one confirmed finding sits inside an invariant the ledger already holds — **twice**.

| class | status | evidence |
|---|---|---|
| `decoder_normalises_away_unknown_bytes_instead_of_rejecting_them` (2026-07-31) | `env_blocked` | names six nodes in `tests/test_wire_bytes_strict.py` — **the file does not exist at `d8ec901`** |
| `canonicity_preserving_perturbation_accepted` (RT-08) | `env_blocked` | `regression_test: "external:proofbundle (RT-08, noch nicht eingepflanzt)"`, `meta_test: "pending"` |

**A correction to the foreman's own synthesis, made here rather than quietly dropped:** it reported
these entries as recorded *handled* while their tests are absent, and concluded the ledger must be
corrected. Measured, both stand at `env_blocked` — the ledger does not lie, and that half of the
finding does not hold.

The point underneath survives and is sharper for it: the ledger did not *lose* the class, it kept
it twice and could not replay it either time. The defect lived 26 days inside two honestly parked
classes and was rediscovered by a lens, not caught by the replay. `env_blocked` is honest **and**
is where defects last — a gap in the mechanism's effect, not a lie in its record. Recorded as
`ZWEI-LEDGER-KLASSEN-BENENNEN-DIE-INVARIANTE-DES-P2-UND-KEINE-HAT-EINEN-LEBENDEN-TEST-01`.

### Standing targets

RT-01 (subject absent/ambiguous/malformed/mismatch), RT-02 (JCS absent in a genuine minimal
install, driven with `python -S`), RT-03 (same-key edge without `verified_under`), RT-04 (malformed
input → stable verdict) — all four explicitly attacked with executable reproducers and all four
confirmed fail-closed, in Python and, where a Rust arm exists, in Rust.

### Declared NOT RUN

`mutation_check` (multi-hour) · full 24 h `fuzz_soak` · `readiness_pack_manifest --check`.
`audit_candidate_matrix` exits 1 by Owner decision (version pin drift, not to be raised for 5.0.0;
its CI job carries `continue-on-error`).

---

## Release recommendation

**Do not tag v5.0.0 on this digest.** One confirmed finding forbids `WITHSTANDS_DEEPGATE` under
canonical v4 §10, and there is no discretion in that.

**Proportion, stated plainly:** the finding is P2, not P0. The reason to fix before the tag rather
than after is not severity — it is that a release shipping two verifiers which disagree about
whether a signed artefact is valid makes a claim it cannot keep.

**The fix is cheap and the sweep is not.** The instance is two lines and changes no wire format for
conforming producers. The class is 27 lax decode sites, two ledger classes whose regression
evidence does not exist, and a Rust differential corpus that is relation-scoped and structurally
blind to this axis. Closing this with a point fixture on `dsse.py` would be the "fix the instance,
not the class" loop this gate exists to catch — and the ledger already shows this class surviving
one such closure.

**Open for the Owner:** whether the class fix lands in 5.0.0 or after 5.1.0 is an Owner decision,
because it changes acceptance behaviour on public verify surfaces — the same criterion under which
`capture_mechanism` was deferred. The difference, offered as argument and not as a decision: this
narrowing makes Python agree with the project's own Rust arm, and RFC 4648 requires it anyway.

**Whatever is decided, the re-gate must run over the NEW digest.** A verdict binds to exactly one.

---

## Iteration 8 — MEASURED; the fix was gated, and the gate found more than the fix

```
graded commit     d478882   src tree f5148088
pre-registration  PRE_REGISTRATION_DEEP_500_ITER8.md, 11525 B,
                  sha256 6a8e4635b5651d801564a7d85990500ad12b9695ff57b0ebf53ed12df82da42c,
                  frozen 2026-08-26T12:05:30Z
pre-sweep         ledger replay pass (161 tests, 80/141, 0 regressed) · full suite 2275 passed,
                  123 skipped, 0 failed · ruff exit 0 · lax decode sites tree-wide: 0 (AST)
agents            48 · 6 lenses · 13 candidates · 8 survived 3-juror refute-to-kill
verdict           FIX_FIRST — 8 confirmed findings, 4 of them P1
```

**RT-04 IS FALSIFIED.** `rt_targets_confirmed` reports RT-01 `true`, RT-02 `true`, RT-03 `true`,
**RT-04 `false`**. The pre-registration holds that RT-01..RT-08 are standing and not removable, so
there is no discretion here and no partial credit: **no tag on this digest.**

### What iteration 7's fix did, and what it did not

The class fix of `L3-500-DSSEB64-02` landed as `d478882` and holds: the wire-decoding family is
strict tree-wide (0 lax sites, AST-measured), the property test is planted under the four node names
the ledger had cited since 2026-07-31, and the gate-meta-test turns it red on the planted lax
fallback. **E13 holds.**

It closed the class it was asked to close. Iteration 8 then found a **different** class in the same
neighbourhood — and, more importantly, found out why nobody had seen it.

### The finding that explains the other seven — L3-05 (P1)

`scripts/type_confusion_gate.py` is a **CI-blocking** gate. It reports `never_raise_ok=true` with
zero violations **while three of its own IN_SCOPE surfaces raise raw `TypeError`s**.

The cause is its generator, not its assertions: the matrix replaces the **entire primary argument**
instead of mutating a **nested leaf**. Every payload it produces is therefore rejected by the outer
shape check *before the inner validators ever run*. Both never-raise assurance lanes — the blocking
gate and the 98-surface pytest lane — are **vacuous for this class**. `is_fail_open=true`.

This is why iteration 7 did not find L3-01/02/03: the assurance lane reported green, and the lenses
believed it.

**A note that belongs in the record rather than in a footnote:** verifying L3-03 for this record, I
made the *same* mistake. I passed `{"status": []}` at the top level of `validate_run_ledger_predicate`,
where `status` is not an allowed field, reported the site as "not reproduced", and only found on a
second attempt that `_validate_run_shape` runs per entry in `runs`. On the nested path it reproduces
immediately. The gate is vacuous for exactly the reason my probe was fruitless: **someone testing a
surface hands it something broken, and thereby hits its entrance, not its interior.**

### The four P1

| id | surface | what escapes |
|---|---|---|
| L3-05 | `type_confusion_gate.py::_exercise` + the 98-surface pytest lane | the assurance itself — a property asserted but not observable |
| L3-03 | CLI `outcome verify` · `verify_outcome_receipt` | raw `TypeError` on a **correctly signed** predicate whose `status` is a JSON array (**RT-04**) |
| L3-01 | **`proofbundle.verify_bundle`** · CLI `verify` | raw `TypeError` when `sd_jwt_vc._sd_alg` is an array — **before any signature check** |
| L3-02 | `proofbundle.verify_key_binding` | same, at `kbjwt.py:219` |

Independently re-measured for this record, with a green control in both directions:

```
validate_outcome_predicate({"status": []})                      -> TypeError (raw)
validate_outcome_predicate({"status": {}})                      -> TypeError (raw)
validate_outcome_predicate({"status": "ok"})                    -> verdict     (control)
validate_run_ledger_predicate({..., "runs":[{"status": []}]})   -> TypeError (raw)
validate_run_ledger_predicate({..., "runs":[{"status":"passed"}]}) -> verdict  (control)
```

**Container types, measured — this is what makes it one class and not four accidents:**

```
outcome._OUTCOME_STATUS        set     hashes the key -> exploitable
run_ledger._RUN_STATUS         set     hashes the key -> exploitable
kbjwt._HASH_ALG                dict    hashes the key -> exploitable
sdjwt._HASH_ALG                dict    hashes the key -> exploitable
statuslist._ALLOWED_BITS       tuple   ACCIDENTALLY safe
policy._SUPPORTED_SCHEMAS      tuple   ACCIDENTALLY safe
```

The last two are the reason a point fix is the wrong altitude: a `tuple` → `set` refactor arms them
silently, and nothing in the tree would notice.

### The four P2

* a **crypto-verified** attached retraction with a malformed `relationships` block is silently
  dropped — `reject_superseded` cannot fire, `ok=true`, `safeForAutomation` unaffected;
* `verify_tlog_proof` carries **no budget at all** — neither an `input_bytes` cap nor a pre-decode
  `merkle_path` cap;
* `verify_cosignature` / `verify_witnessed_checkpoint` cap neither note bytes nor cosignature-line
  count, and the O(W×L) witness scan runs unconditionally;
* the **shipped** auditor `REPRODUCTION_RUNBOOK` step 2 invokes `--check-determinism`, a flag that
  does not exist.

### The vacuity, quantified on the gate's own population

Measured by running `type_confusion_gate.evaluate()` against `d478882`:

```
IN_SCOPE        21 surfaces   — of these, receiving extra kwargs: 0
NON_JSON        26 surfaces   — of these, with a "backed" deferral: 26
NEEDS_FIXTURE    0
never_raise_ok  True          — violations: 0
```

**The gate exercises the right surfaces and sees nothing on them.** That is more precise than "the
matrix is wrong": the selection is sound, the inputs do not reach past the outer shape check. Among
those 21 are the four sites iteration 8 confirmed to raise raw `TypeError`s on a nested value.

**The second half is larger than the first and was under-stated in the finding as first written:**
26 surfaces are excluded outright as `NON_JSON`, every one of them behind a deferral the gate marks
as *backed*. A deferral pointing at a test file that exists but does not cover this class is the
same defect type as a ledger class naming a test that does not exist — one degree milder: the file
is there, the coverage is not. The foreman's remediation asks for exactly these to be re-included
by mutating the inner JWT payload rather than deferring on the primary's type.

So the generator repair has **two halves**: nested-leaf mutation across the 21, and re-inclusion of
the 26.

**A correction to a number this record carried in an earlier draft:** "13 of 19 surfaces need
fixtures" was measured over `dir(proofbundle)` — a *different population* than the gate's, which is
derived by `discover_python_verify_functions`. In the gate's own set the fixture bottleneck does
not exist at all (0 of 21 need extra kwargs). Measuring the right thing over the wrong population
is the recurring error of this release, and it belongs in the record rather than in a quiet edit.

### The remediation is the generator, not the guards

Four `isinstance` guards would close four instances and rebuild the class next door. The repository
has already paid for exactly that three times — `statuslist.py:122`, `kbjwt.py:151`, `kbjwt.py:230`
each hardened the **outer** argument of a function whose **inner** field still crashes today.

The acceptance criterion for closing this class is therefore not the guards but a **failing
meta-test that starts passing**: inject an unguarded membership test into a randomly chosen IN_SCOPE
surface and the gate must report at least one violation. It does not today.

### Honest boundary of this section

`WITHSTANDS_DEEPGATE` was not reached and is not claimed. The tag, the merge to main, the GitHub
release, the PyPI publish and the deposit remain five separate Owner acts, and the decision on how
to proceed — generator first, P1 only, or defer 5.0.0 — is an Owner decision recorded as a card, not
a conclusion of this record.
