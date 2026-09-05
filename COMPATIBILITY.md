# Compatibility and deprecation

What SemVer means here concretely, what counts as a breaking change, how long a deprecated thing
stays, and which parts are exempt because they are labelled EXPERIMENTAL.

**Nothing on this page is a new promise.** README already states the project is SemVer-committed;
this file writes down what that sentence already implies, so that a reader does not have to infer it
and a maintainer cannot quietly narrow it.

## What counts as the public interface

Compatibility statements are worthless without naming the surface they cover. For proofbundle it is:

1. **The Python API** — names importable from `proofbundle` and its documented submodules, their
   parameters, and the **shape of what they return**.
2. **The CLI** — subcommands, flags, and the meaning of exit codes.
3. **The emitted bytes** — the receipt/bundle formats, the in-toto Statement and the DSSE envelope.
   A signed structure is an interface even when no function signature changes.
4. **The verification verdict** — whether a given input verifies. A change that makes previously
   valid input invalid is breaking even if every signature stayed the same.

Point 3 is the one that is easy to miss, and it is the reason `stash@{0}` did not ride along in
3.7.1: adding one key to a per-edge result entry changes a structure that ends up signed. Measured,
recorded in [`docs/release_scope/3.7.1.md`](docs/release_scope/3.7.1.md), and kept out of a PATCH.

## What is a breaking change

- Removing or renaming anything in the four surfaces above.
- Changing the **type** or **meaning** of a field, including a field that is only ever read.
- **Adding** a field to an emitted, signed structure — the bytes change even though nothing was
  taken away.
- Making a previously accepted input fail verification.
- Turning an optional obligation into a required one.

**Not breaking:** new optional CLI flags, new functions, additional keys in a structure that is
neither signed nor part of a documented return shape, documentation, tests, build tooling, and
performance. Tightening a check that only ever accepted input the spec already called invalid is a
fix, not a break — and the CHANGELOG entry has to say so explicitly, because from the outside a
stricter check and a break look identical.

**5.0.0, worked example.** Both MAJOR triggers of 5.0.0 (recorded in [`docs/release_scope/5.0.0.md`](docs/release_scope/5.0.0.md)) are the two rules above made concrete: an input class that used to exit **2** (malformed/usage) now exits **1** (a crypto failure / verdict) — the meaning of an exit code changed, and exit codes are surface 2; and the Inspect lifecycle hook and the pytest plugin now **require** `PROOFBUNDLE_THRESHOLD` instead of silently defaulting it to `0` — an optional obligation made required. Neither flips a verdict: nothing that verified before stops, nothing that failed starts. Migration is one line: `export PROOFBUNDLE_THRESHOLD=0`.

## What each version step allows

| Step | Allowed |
|---|---|
| PATCH (`x.y.Z`) | fixes only. **No semantic change, no new obligation, no changed behaviour at a public interface.** |
| MINOR (`x.Y.0`) | additive changes, new optional fields, new commands, deprecation *announcements* |
| MAJOR (`X.0.0`) | removals, renames, meaning changes — that is, everything above |

That PATCH row is not decoration: it is the question the release gate in [RELEASE.md](RELEASE.md)
makes someone answer per line of the scope list, in writing, before a release is asked for.

## How long a deprecated thing stays

**A deprecated stable element is removed no earlier than the next MAJOR.** That is not an extra
guarantee — it is what SemVer already means, written down so nobody has to derive it. In practice:

1. The deprecation is announced in the CHANGELOG of the MINOR that announces it, and the element
   keeps working unchanged.
2. It stays through every following MINOR and PATCH of that major line.
3. It may be removed in the next MAJOR, and that removal is named in the CHANGELOG.

**No calendar.** No "six months", no "two releases" — a period nobody schedules is a promise that
breaks itself. The bound is the next MAJOR, and MAJORs happen when they happen.

**Honest limit:** as of this writing no stable element has gone through the full cycle, so this
describes a rule, not a track record. It is written down precisely because a rule that only exists
in someone's head is not one.

### Deprecated in 6.0.0

**`build_agent_review_statement(v02=...)` and `emit_agent_review(v02=...)`.** From 6.0.0 the emitter
produces `agent-review/v0.2` without any argument; the previous version comes from an explicit
`legacy_v01=True`. The `v02=` argument keeps working and raises a `DeprecationWarning`; it may be
removed in a later MAJOR, and that removal will be named here.

Why the argument goes and not just its default: `v02=False` says what is NOT chosen, and a reader
cannot tell from it what arrives instead. `legacy_v01=True` names the thing it selects. Passing both
at once is an error rather than a silent precedence — two versions cannot both be the answer, and a
quiet winner would swallow one of the two intents without the caller ever learning.

**Coverage aliases (from the release that carries CAP-1 coverage).** In `agent-review/v0.2` the
fields `observedRuns`, `expectedRuns`, `knownGaps` and `collectionMethod` under `coverage` are
aliases for the accounting that `strata`, `integrity` and `absenceAssertions` carry in the language
of `draft-hillier-coverage-attestation-00`. They stay readable, keep their meaning, and a predicate
that carries only them verifies as before (with the advisory code `COVERAGE_LEGACY_FIELDS`). Their
removal is not before the next MAJOR and will be named here; nothing in this line changes their
behaviour.

**What is NOT deprecated:** `agent-review/v0.1` itself. It stays readable and verifiable, its verifier
is byte-pinned to the 5.1.0 source (a test resolves `git show v5.1.0:` and compares), and six published
receipts depend on exactly that. Emitting it is now a deliberate act; reading it is not.

## What is EXPERIMENTAL, and what that costs you

EXPERIMENTAL parts are **excluded from all of the above**. They may change or disappear in any
release, including a PATCH, without a deprecation period. That is the whole point of the label: it
buys the freedom to get a design wrong in public.

Currently labelled EXPERIMENTAL (see CHANGELOG and README for the authoritative statement per
release):

- **`relation/v0.1`** — the relation/lineage surface
- **`agent-review/v0.2`** — the current agent-review predicate (see the table above; README says
  the same). What the 6.0.0 deprecation above protects is the EMITTER ARGUMENT `v02=` on a shipped
  function, not the predicate's status: the argument keeps working until a later MAJOR, the
  predicate may still change.
- **the `[experimental]` extra** — the TEE-attestation bridge, see
  [docs/EXPERIMENTAL_ENCLAVE.md](docs/EXPERIMENTAL_ENCLAVE.md)

The `eval-result` predicate is a further case and is labelled separately: its `predicateType` sits
in a **vendor namespace** until in-toto registers the type, and the migration path (registered URI
plus alias) is written down in [docs/IN_TOTO_PROFILE.md](docs/IN_TOTO_PROFILE.md). Consumers match
on the subject digest, so that rename does not affect binding.

The current release line as a whole carries a status boundary of its own (audit-candidate **BETA**),
stated per release in the CHANGELOG. A BETA line still follows the table above; the label says how
much external assurance exists, not how freely the interface may move.
