# Finding — the never-raise family property is green over an incomplete population

**Pre-existing (`main`). Reported first, then CLOSED IN THIS RELEASE** under the Owner's instruction
that all gaps be closed inside 3.8.0. Its subject exists at `v3.7.0`, so it stays an Altbefund in the
index count; only its state changed. Recorded here because the deep-gate run on the
3.8.0 candidate surfaced it, and because it bears on what a class-closure claim in this repository is
worth.

**This file does not assert that a pre-tag audit ran.** The N-lens jury has not completed.

## The claim under test

`tests/test_never_raise_surface_family_property.py` is the executable form of the never-raise class:
no public surface may terminate with a raw exception on hostile input. The 3.6.3 release closed that
class, and the property is the evidence.

## What was measured

Two planted defects, identical in kind, in a throwaway copy of the candidate tree
(`git archive HEAD | tar -x`, the candidate worktree was never written to):

| Plant | Module in `_MODULES`? | Family test result |
|---|---|---|
| `raise RuntimeError(...)` at the head of `anchors.verify_anchors` | **yes** | `FAILED (errors=1)` — caught |
| `raise RuntimeError(...)` at the head of `anchors_ots.verify_opentimestamps` | **no** | `Ran 5 tests ... OK` — **not caught** |

Bidirectional validation as v4 requires: green on known-good, red on known-bad. The test is not
broken. It is correct over the set it walks, and that set is smaller than the set it is read as
covering.

## The population gap, enumerated

`_MODULES` in that test lists **36** modules. The package ships **50**. A sweep over the difference,
applying the test's own `_NAME_PATTERN`, finds **11 never-raise surfaces across 7 modules that the
property never enters**:

```
anchors_chia        2  verify_offline_merkle, verify_chia_datalayer
anchors_markovian   1  verify_markovian
anchors_ots         1  verify_opentimestamps
anchors_rfc3161     1  verify_rfc3161
anchors_rootcommit  2  verify_rootcommit_v1, verify_rootcommit_v2sig
emit                1  load_signer
pqsig               3  verify_mldsa, verify_slhdsa, verify_hybrid
```

All eleven match the test's own name pattern. They are absent for one reason only: their **module** is
not in `_MODULES`. Nothing about them is out of scope by intent — the list is hand-maintained.

## Why this matters beyond the count

One of the eleven is already known to violate the contract. The self-gate run of 2026-07-31 recorded
F3: `anchors_rfc3161.verify_rfc3161` raises `AttributeError` on a non-dict `frozen` / `rp_trust`,
breaking the never-raise rule that `register_anchor_type` prescribes to third-party authors. Measured
again today against `main` `ac0688c`, with `[anchors]` installed so the code actually reaches the
lines:

```
rp_trust=123 (non-dict)      -> AttributeError: 'int' object has no attribute 'get'
frozen=123  (non-dict)       -> AttributeError: 'int' object has no attribute 'get'
frozen=123 + valid rp roots  -> no raise, ok=False, status=chain_fail
```

It still reproduces sixteen days later. It survived the 3.6.3 class fix not because the fix was wrong
but because the population never contained it.

## The class

- **class_id:** `family_property_green_over_a_hand_maintained_population_that_omits_members`
- **invariant:** a property that claims to close a class must enumerate its family from the tree, not
  from a maintained list; otherwise "green" measures the list, not the class.
- **surface_family_query:** every module under `src/proofbundle/` exporting a function whose name
  matches the property's own `_NAME_PATTERN`, discovered at run time.
- **oracle_predicate:** plant a raw raise in a discovered surface; the property must go red. A surface
  where it stays green is outside the population and the claim does not cover it.
- **outcome:** `class_closed` on the MODULE axis — the property enumerates its family from the tree.
  The keyword-argument axis is a different one and stays open, see below.

## How it is closed, and what the closing measured

`_MODULES` is gone as the population. `_module_names()` walks `proofbundle.__path__` with
`pkgutil.walk_packages`, so subpackages come along and a newly added module is in scope the day it
lands rather than the day someone remembers the list. Measured: 36 listed modules against 62 in the
tree; 79 surfaces against 91.

**The decisive probe, which is the finding's own experiment run in both directions:**

```
tree + planted raise in anchors_ots        -> RED   (caught)
tree + planted raise in anchors (listed)   -> RED   (no regression)
LIST + the same raise in anchors_ots       -> GREEN (the finding, reproduced)
baseline                                   -> GREEN (returns exactly)
```

**One live defect fell out immediately, and it is not the one this file predicted.**
`emit.load_signer` had never been swept. `open()` accepts an **integer as a file descriptor**, so
`load_signer(123)` did not fail on the wrong type — it read whatever was open on fd 123 and tried to
make a private key of it. A wrong-typed argument silently reaching an unrelated open file is a worse
outcome than a crash. Guarded at the surface with a typed error, held by
`tests/test_load_signer_fd_hazard.py`, which proves the descriptor is **not read** (it is still open
afterwards) rather than merely that something was raised.

**The instrument itself had two states where it needed three.** A surface terminating with anything
outside both the accepted and the forbidden set crashed the run with a traceback instead of
producing a finding — measured on exactly that `OSError`. `_FORBIDDEN` is a blocklist over an open
alphabet; what is not on it is **unclassified**, not permitted. It is now reported as its own
category.

**A loosening that had to bring its own guard.** Accepting `OSError` was necessary once a
path-taking surface entered the family — *the file is not there* is an honest typed answer for a
loader, and counting it as a violation would make the property unbelievable, and an unbelievable
property gets switched off. But that same line would have re-hidden the fd hazard, which is why the
hazard is closed at the surface and pinned by its own test rather than by the list.

**STILL OPEN, and it is this file's own prediction:** `anchors_rfc3161.verify_rfc3161` raising
`AttributeError` on a non-dict `frozen` / `rp_trust` lives on the **keyword-argument** axis. This
property fuzzes the PRIMARY argument, so closing the module axis does not reach it — the same shape
as F2 ("the class sweep plays only argument position 0"), one axis over. Not fixed here, and named
so the closure is not read as wider than it is.

This is the same shape as the finding the 31.07. run recorded as F2 ("the class sweep plays only
argument position 0"), one level up: there the *argument* axis was truncated, here the *module* axis
is. Both make a green print mean less than it reads.

## Honest boundary

The candidate's own delta is unaffected by THIS finding: targets F1 through F7 were measured against it
separately.

**RETRACTED 2026-08-16, two errors in the two lines above.** They said "`src/proofbundle/cli.py`,
+14 lines" and "each held". Neither survived measurement. The shipped delta over 3.7.0 is **two** files
under `src/` — `cli.py` (+14/−2) and `__init__.py` (+1/−1, the version line) — and both go into the
wheel; the same "one file" slip was corrected in the CHANGELOG and left standing here. And F5, F6 and F7
**fell** once the falsification pass was pointed at its own record; see `FALSIFICATION_F1_F7.md`. All
three were grading errors of mine rather than defects in the release, which does not make the sentence
any less wrong.

It is corrected here rather than left to a reader because a counter-read found the two files in this
same directory saying "each held" and "THREE FELL" about the same seven targets. A record that
contradicts its neighbour is worse than one that is merely incomplete: both halves look measured.

This finding concerns code that shipped in 3.7.0
and the instrument that measures it. Whether it should block a 3.8.0 verdict is not decided here —
it is put in front of the decision rather than into a footnote, which is what the methodology requires
of a confirmed finding.

## Nachtrag nach der Gegenlesung — zwei Korrekturen an diesem Dokument selbst

**Der benotete Digest, den dieses Dokument nie genannt hat.** Abschnitt 9 der Praeregistrierung
verlangt, dass ein Record den Digest NENNT, den er benotet. Dieses Dokument tat es nicht — es
referenziert `git archive HEAD | tar -x` ohne Pin. Der benotete Stand ist **`f64d35e`**; die
Messungen an `main` beziehen sich auf **`ac0688c`**.

**"11 never-raise surfaces across 7 modules" ist top-level-only.** Der eigene `surface_family_query`
sagt "every module under `src/proofbundle/`". Gemessen ueber den ganzen Baum:

```
Top-Level-.py ohne __init__ : 53      alle .py inkl. Unterpaketen : 63
Sweep ueber Top-Level       : 11 Flaechen / 7 Module   (die Tabelle oben)
Sweep inkl. Unterpaketen    : + proofbundle.experimental.enclave.verify_enclave_attestation
=> real                      : 12 Flaechen / 8 Module
```

`experimental.enclave` wird ausgeliefert, ist dokumentierter Importpfad UND CLI-Unterbefehl
`verify-enclave`. Gemessen hat es heute **0 Verstoesse** — eine Populationsluecke ohne lebenden
Defekt. Aber es ist dieselbe Klasse, die dieses Dokument berichtet, eine Ebene tiefer: der Sweep,
der eine handgepflegte Liste als zu eng entlarvt, ist selbst zu eng. Und `:47` sagt ausdruecklich
"Nothing about them is out of scope by intent" — das Unterpaket ist also nicht bewusst
ausgeschlossen, sondern uebersehen.
