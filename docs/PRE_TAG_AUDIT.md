# Pre-tag adversarial audit (Front-Load F7 discipline)

**The six-lens / master-prompt-v2 adversarial internal audit runs before EVERY release tag, not only
before the audit-candidate (3.6.0).**

## Why

On 2026-07-16 an EXTERNAL reviewer (Loek) found the decoy-parent structural issue (F1) *after* 3.3.0
had shipped. Structural problems are cheapest to fix when they surface early. Running the adversarial
audit before every tag (3.4.0, 3.5.0, 3.6.0, ...) means a 3.4.0-class structural problem is caught at
3.4.0, where it is cheap, instead of just before the paid external audit, where it is expensive. The
cost is low (the master-prompt already exists); the benefit is avoiding exactly the late rework the
front-load program exists to prevent.

## The mechanised gate

`scripts/pre_tag_audit_gate.py` enforces that the audit was actually run for the release being
tagged. It is wired `--strict` into `release.yml` as the first blocking step, so a `v*` tag without
a valid record fails before it can build or publish.

```bash
python scripts/pre_tag_audit_gate.py --version X.Y.Z --strict
```

**What counts as a record: a signed receipt. Prose does not.** The gate verifies an ed25519-signed
receipt (`b7n0de.pre_tag_audit_receipt.v1`, produced by `scripts/pre_tag_receipt.py`) that is bound
to the digest of the tree being tagged. The public half of the signing key is read from the
**committed** tree (`git show HEAD:audit_artifacts/pre_tag_trusted_pubkeys.txt`), never from the
working tree — otherwise a checkout could inject a key and self-sign.

**This section used to say something else, and following it would not have worked.** Until
2026-09-15 it described the original mechanism: a CHANGELOG line, or an `audit_artifacts/` file
carrying an audit marker. That is what the gate read *until* it was rewritten, and a maintainer
following the old text would write a CHANGELOG line and find the gate unsatisfied — or, worse,
assume it was satisfied. The change to a signed receipt landed in the code; this page did not
follow it.

The reason the mechanism changed is worth carrying here rather than leaving in the ADR: on
2026-08-16 the gate was satisfied **by a documentation edit**, for a release with no audit record.
A blocklist of negations over prose is a blocklist over an open alphabet — each round finds the
next sentence not on the list. A signature is not enumerable that way. The property test
`tests/test_pre_tag_gate_eigenschaften.py` pins this:
`test_P4_eine_prosa_zeile_erteilt_keinen_pass_mehr` feeds the exact canonical truthful prose
line and asserts the gate does **not** grant on it.

**How the receipt is produced, since 2026-09-21.** `scripts/pre_tag_receipt.py` starts the
audit itself: it measures the checkout clean and equal to `HEAD`, runs `--audit-command` as a
program in the tree, measures again, and only then builds the context whose `audit_exit_code`
is what the program returned and whose `audit_output_digest` is the sha256 of the bytes it
captured into `--audit-output-file` (a path outside the tree that did not exist before). A
typed exit code and a supplied record are refused, because neither can be bound to a run that
was measured; a counter-reading had shown that an output produced from a modified tree, with
the file restored afterwards, was bound to the clean head. The cleanliness measurement does not
ask git whether the tree is clean, because git answers through its configuration: it is COMPUTED
from the bytes on disk. Every entry of `git ls-tree -r HEAD` is hashed as a blob with
`git hash-object --no-filters` and compared with the committed object id, its mode is read from
the file itself, a symbolic link's target is hashed, and a missing or foreign entry refuses by
name; staged content is compared with `HEAD` on the real index; untracked paths are judged on a
fresh index against the tree's own ignore files only, with the working tree named on the command
line. Ten states outside the committed tree had each hidden a path from an earlier version, and
each has a case that was red against it: `status.showUntrackedFiles`, a global excludes file,
`.git/info/exclude`, an untracked ignore file covering itself, `GIT_DIR`, the index bits
`assume-unchanged` and `skip-worktree`, a clean filter defined in the configuration,
`core.worktree` and `core.fileMode`. The price is named: a checkout whose files differ from their
blobs by design (`core.autocrlf=true`, no executable bit, `core.symlinks=false`) refuses. What two
point measurements cannot see, and the script says so: a change made and undone during the run.

**Honest limit, and it is not small.** The trust root is a key committed in this repository, the
same one whose release the verdict concerns. A third party can verify the signature if they clone
the repository, but they cannot establish the authority behind it from outside, and the receipt is
not shipped with the release. See the closing section of `RELEASE.md` for what that means for
someone verifying a published release.

## What the audit itself must cover (the checklist the gate cannot read for you)

The gate proves the audit was *recorded*; the human/agent running it is responsible for its *content*.
Each release's adversarial pass should, at minimum:

1. Run the six-lens review (correctness / No-Fake / adversarial / SOTA / regression / fidelity).
2. Attempt to REFUTE the release's new invariants, not only confirm them.
3. For a release that adds a verifier or a vector kind: confirm F1 (one vocabulary), F3 (a new formal
   obligation if the logic changed), F4 (the new verifier is auto-covered or honestly NEEDS_FIXTURE).
4. Record named findings + closed fixes in the CHANGELOG section. **That is documentation, not
   what the gate reads** — the gate reads the signed receipt (see above). Both are expected; only
   one of them grants the pass.

## Where each release drops its audit evidence

Into the readiness pack (`docs/readiness_pack/index.json`, the release's named slot) and the CHANGELOG
section. The reserved slots for 3.4.0 / 3.5.0 / 3.6.0 are already laid out (Front-Load F5).

## The mutation gate has two roles, and they are not interchangeable (2026-09-02)

Since the sharding change there are **two** ways to run `scripts/mutation_check.py`. They measure
the same thing and are used at different moments. Confusing them is the failure this section exists
to prevent.

| | canonical full run | sharded PR gate |
|---|---|---|
| command | `python scripts/mutation_check.py` | `--shard i/K`, K jobs in the CI matrix |
| when | **before every tag** (step B1 of the release run), plus nightly on the Farmer | on every pull request |
| operators | all 88 in one process, sequentially | 88 split deterministically across K jobs |
| per-mutant suite | full | minus the named exclusion list |
| wall clock | ~100 min measured 2026-09-02 | longest shard, K=10 → ~1005 s projected |
| what it settles | the release verdict | whether this change broke the gate |

### Why both measure the same thing

The verdict of an operator is differential: a mutant is KILLED when it is *strictly more red* than
the baseline of the same run. The exclusion list removes tests that query the **repository** — the
candidate matrix builds two sdists and compares them byte for byte — and never read the mutated
source. Removing them shifts the mutant and the baseline by the same amount, so the difference, and
with it the verdict, is unchanged.

**That sentence describes the design. Until 2026-09-02 the code did something else, and this
paragraph asserted a property the code did not have.** `baseline` and `final` ran *without* the
exclusion while the per-mutant run used it — two different test sets on the two sides of one
difference. The bias runs toward **false SURVIVED**: if an excluded test goes red, only the
baseline rises, and a real kill is silently recorded as a survivor.

It was latent, not harmless. Measured on 2026-09-02 with **one** planted failing test in
`tests/test_audit_candidate_360.py`, shard 1/10 turned **three of nine** operators from KILLED into
SURVIVED — `bundle: expected_aud/nonce downgrade-trap`, `renewal: R1 require_current_hash floor`,
`dsse: pre-decode base64 payload DoS cap`. A test the gate no longer looks at decided three
verdicts. With the same planted test and symmetric measurement, the same shard reports
`OK (9 operators, 0 gaps)`.

All three call sites now pass `ausschluss=True`, so the two numbers in `red > baseline` come from
the same set.

### Who measures the excluded module, now that the gate does not

The gate never asserted the health of `tests/test_audit_candidate_360.py`; it asserted that no
*mutant* is caught by it. That module's own health is covered elsewhere, and deliberately so:

* the **binding `test` jobs** of the same CI run the full suite on every push, this module included;
* the **canonical full run** before every tag runs the complete suite in one process.

Dropping it from the gate's per-mutant suite therefore removes 78 % of the runtime and no coverage.
What it *did* remove, until the fix above, was the symmetry of the comparison.

That is an argument, and arguments are not evidence. It was therefore **measured**: the full
88-operator run with the exclusion active reproduced the canonical result exactly — 87 KILLED,
1 expected SURVIVED (`cosign: blob length exact -> lax (EQUIVALENT)`), 0 gaps. No operator died only
through an excluded test; had one, the count would not have reached 87.

### Why the canonical run stays

The sharded gate answers a narrower question. It runs in K separate processes on a runner we do not
control, and its per-mutant suite is smaller by construction. Before a tag we want the widest
statement the tool can make, from one process, with the complete suite — and cheap enough to keep,
because it runs once per release rather than once per push.

**A tag is never cut on a sharded run alone.**
