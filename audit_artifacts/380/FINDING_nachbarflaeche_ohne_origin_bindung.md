# Finding — `verify --trusted-checkpoint` takes a checkpoint from any log, and no flag can bind it

**Pre-existing (`main`), reported and not changed here.** This is the direct neighbour of the hole
3.8.0 closes, on a surface the release does not touch. It is recorded because a lens triggered it
rather than reasoned about it, and because it is the most consequential open item this round found.

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
- **outcome:** `class_open`.

## Why it is not fixed in this release

Adding `--expected-origin` to `verify` is a **new public flag on a second surface**, plus a new
parameter on `verify_witnessed_checkpoint`. That is a capability change, not a test addition — it
belongs in a release that announces it, with its own near-miss corpus (the corpus this release just
learned it needs), not appended to a tag that is being cut. The surface is on `main` and predates
3.8.0.

Stated plainly so the deferral is not mistaken for a judgement about severity: **this is the most
serious open finding of the round.** A relying party using `verify --trusted-checkpoint` today gets
root authenticity from *some* log and cannot require *which*, which is precisely the threat model
`--expected-origin` exists to answer.

## Honest boundary

The measurement shows the verdicts are indistinguishable and that no flag exists. It does **not**
show that a real deployment is exposed: whether an attacker can get a relying party to pass an
attacker-chosen checkpoint depends on how that checkpoint reaches them, and that is outside what a
repository measurement can settle.
