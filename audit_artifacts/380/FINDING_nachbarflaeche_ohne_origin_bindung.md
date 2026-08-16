# Finding — `verify --trusted-checkpoint` takes a checkpoint from any log, and no flag can bind it

**Pre-existing (`main`). Reported first, then CLOSED IN THIS RELEASE by Owner order
`OA-a41a514b63`** ("noch in 3.8.0, verzoegert den Tag deutlich"). The classification does not
change — its subject exists at `v3.7.0`, so it stays an Altbefund in the index count — but its
state does: it is no longer open. The section "Why it is not fixed in this release" is kept below
under its own heading, because the reasoning that recommended deferral is part of the record and
the Owner overruled it deliberately, not because it was wrong on the facts.

This is the direct neighbour of the hole 3.8.0 closes. It is recorded because a lens triggered it
rather than reasoned about it, and because it was the most consequential open item this round found.

**Nothing in this file asserts that a pre-tag audit ran.**

## What 3.8.0 fixed, and where the same hole still is

`verify-proof --expected-origin` lets a relying party pin the checkpoint origin, so a validly signed
checkpoint from a *different* log is rejected. That was the release's one capability change.

`verify --trusted-checkpoint` takes a signed checkpoint note as an **authenticated source for the
root and the tree size** — and has no way to say which log it must come from.

## Measured, by triggering it

One bundle, two validly signed checkpoints over the **same root**, with the **same key**, differing
only in origin:

```
verify … --trusted-checkpoint cp_real     -> rc=0
  [PASS] checkpoint-authenticity: origin 'log.example.org'     … ROOT-AUTHENTICITY: PASS
verify … --trusted-checkpoint cp_foreign  -> rc=0
  [PASS] checkpoint-authenticity: origin 'boesewicht.example'  … ROOT-AUTHENTICITY: PASS

proofbundle verify --help | grep -ci origin   -> 0
```

Byte-identical verdict, `root-trust-level CHECKPOINT` in both, and **no flag exists** with which the
verifier could bind the origin. The library sibling `verify_witnessed_checkpoint` has no
`expected_origin` parameter either.

The display on that path is sound — it interpolates with `{…!r}`, and `repr()` was measured to
neutralise both ESC and zero-width characters. The gap is the **binding**, not the rendering.

## The class

This is the same class as `FINDING_erwartungsvergleich_klasse.md`, one level up: there the *evidence*
for an exact comparison was missing on six neighbouring surfaces; here the *capability to compare at
all* is missing on one. Both come from fixing an instance and not sweeping its neighbours.

- **class_id:** `origin_binding_offered_on_one_verify_surface_and_absent_on_its_sibling`
- **invariant:** where a signed artifact carries the identity of its issuer, every verify surface
  that consumes it as an authenticated source must let the relying party pin that identity — not
  only the surface where the gap was first noticed.
- **surface_family_query:** every CLI subcommand and public function that accepts a signed
  checkpoint, note or statement as trusted input.
- **oracle_predicate:** build the same artifact under two different issuer identities and verify
  both. If the verdicts are indistinguishable and no parameter can separate them, the surface has no
  binding.
- **outcome:** `class_closed` — both members of the family now carry the binding
  (`verify-proof --expected-origin` and `verify --expected-origin`), the library sibling
  `verify_witnessed_checkpoint(expected_origin=…)` with them.

## A second measurement, taken while closing it — the key does not bind the origin either

The measurement above used two origins under one key and showed the verdicts were
indistinguishable. Closing the finding required asking what a pinned key actually guarantees, and
the answer is weaker than it looks:

```
note = sign_checkpoint("evil.example/other-tree", 7, ROOT, k, "example.com/log")
vk   = vkey("example.com/log", raw_pub(k))          # the TRUSTED key
verify_checkpoint(note, vk)  ->  ok=True   origin='evil.example/other-tree'
                                 tree_size=7   root == our root
```

`sign_checkpoint` takes the origin line and the signature-block name as **separate** arguments, and
C2SP permits one signer to serve several origins. So a note naming a foreign tree verifies under the
trusted key and its `(root, tree_size)` is adopted as the authenticated tree context. Pinning the
key is therefore not a substitute for pinning the origin — which is the strongest available argument
that the flag is load-bearing rather than ceremonial, and it was measured, not assumed.

## How it is closed

- `--expected-origin` on `verify` (same flag name and semantics as `verify-proof`, since it is the
  same property), bound into `cp_ok` — the one variable every consumer already reads, so
  `treeContextAuthenticity`, `treeSizeExpectation` and `safeForAutomation` follow without a parallel
  path.
- `expected_origin=` on `verify_witnessed_checkpoint`, written character-for-character like
  `tlogproof.verify_tlog_proof` so the two do not drift into two spellings of one property.
- A mismatch names itself (`is not the expected …`) instead of reading like a broken signature.
- Default unconstrained on both, matching the sibling: there is no origin a verifier could honestly
  default to. The limit is stated in SPEC.md §9 normatively rather than left to be inferred, and an
  unpinned run keeps reporting the origin it observed.
- **Two** comparison sites, so the shared corpus (`tests/_beinahe_treffer.py`) runs against both.
  Six rollback probes: each comparison loosened to `startswith`, each binding removed entirely, each
  `is None` weakened to a falsy test. All six turn the guards red; the baseline returns exactly.

## Why it was not fixed in this release — the reasoning at the time, overruled by the Owner

Adding `--expected-origin` to `verify` is a **new public flag on a second surface**, plus a new
parameter on `verify_witnessed_checkpoint`. That is a capability change, not a test addition — it
belongs in a release that announces it, with its own near-miss corpus (the corpus this release just
learned it needs), not appended to a tag that is being cut. The surface is on `main` and predates
3.8.0.

Stated plainly so the deferral is not mistaken for a judgement about severity: **this is the most
serious open finding of the round.** A relying party using `verify --trusted-checkpoint` today gets
root authenticity from *some* log and cannot require *which*, which is precisely the threat model
`--expected-origin` exists to answer.

That last paragraph is why the Owner's answer went the other way: a release that names the threat in
its own record and ships without closing it hands the reader a documented hole. The cost the
deferral was protecting against — a delayed tag — was accepted explicitly.

## Honest boundary

The measurement shows the verdicts are indistinguishable and that no flag exists. It does **not**
show that a real deployment is exposed: whether an attacker can get a relying party to pass an
attacker-chosen checkpoint depends on how that checkpoint reaches them, and that is outside what a
repository measurement can settle.
