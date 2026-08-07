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

## What is EXPERIMENTAL, and what that costs you

EXPERIMENTAL parts are **excluded from all of the above**. They may change or disappear in any
release, including a PATCH, without a deprecation period. That is the whole point of the label: it
buys the freedom to get a design wrong in public.

Currently labelled EXPERIMENTAL (see CHANGELOG and README for the authoritative statement per
release):

- **`relation/v0.1`** — the relation/lineage surface
- **the `[experimental]` extra** — the TEE-attestation bridge, see
  [docs/EXPERIMENTAL_ENCLAVE.md](docs/EXPERIMENTAL_ENCLAVE.md)

The `eval-result` predicate is a further case and is labelled separately: its `predicateType` sits
in a **vendor namespace** until in-toto registers the type, and the migration path (registered URI
plus alias) is written down in [docs/IN_TOTO_PROFILE.md](docs/IN_TOTO_PROFILE.md). Consumers match
on the subject digest, so that rename does not affect binding.

The current release line as a whole carries a status boundary of its own (audit-candidate **BETA**),
stated per release in the CHANGELOG. A BETA line still follows the table above; the label says how
much external assurance exists, not how freely the interface may move.
