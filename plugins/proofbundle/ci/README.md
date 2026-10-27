# The proofbundle check in CI

Two templates for the repository whose evidence the plugin gate checks. They are not workflows of
proofbundle itself, and nothing here runs until you copy it into your own repository.

| File | Copy to | What it does |
|---|---|---|
| `proofbundle-evidence.yml` | `.github/workflows/proofbundle-evidence.yml` | A reusable workflow that runs the gate's CI mode on the commit under review. |
| `CODEOWNERS.template` | `.github/CODEOWNERS` | Puts `.proofbundle/`, the two workflows and CODEOWNERS itself under a required review. |

## What the check decides

The CI mode is the gate's own evaluation of HEAD (DECISIONS.md, D22), stricter than before a push.

| Case | Exit | `outcome` |
|---|---|---|
| Every declared item verified and names the tree of the commit | 0 | `verified` |
| Nothing is declared, and `require-declaration` is false | 0 | `not_required` |
| Nothing is declared, and `require-declaration` is true | 1 | `declaration_required` |
| Any other NOT MEASURED (an empty list, a declaration only in the working tree, no repository) | 1 | `not_measured` |
| Any deny of the gate (stale subject, missing file, unpinned policy, failed verification, not bound, a verifier that cannot start, a malformed declaration) | 1 | `failed` |
| The gate was called wrongly | 2 | none |

The check prints one JSON report on stdout (`outcome`, `exit_code`, `require_declaration`, `repo`,
`head`, `verdict`, `reason_id`, `digests`, `message`, `gate_version`) and the message on stderr. The
message has the gate's form: the evidence, what failed, the next step, and the rule never to weaken the
declaration, a policy or a key to get past the check.

A pass proves what the gate proves: who signed the recorded bytes and which tree they name. It does not
prove that any recorded value is true.

## Calling it

```yaml
# .github/workflows/evidence.yml of your repository
name: evidence
on:
  pull_request:
  push:
    branches: [main]
jobs:
  proofbundle:
    uses: ./.github/workflows/proofbundle-evidence.yml
    with:
      require-declaration: true
      proofbundle-ref: <the full commit SHA of b7n0de/proofbundle you reviewed>
```

For a binding check, set `require-declaration: true` in the caller, in a file the code owners review;
`false` is a waiver, not a pass. Then make the job a required status check of the branch, require a code
owner review, and dismiss stale approvals on new commits, so a later change (for example flipping
`require-declaration` to `false`) cannot ride an old approval.

- `require-declaration` has no default. The caller decides, in a file CODEOWNERS covers.
- `proofbundle-ref` must be a full 40-character commit SHA, and it must be contained in a `v*` release tag
  of b7n0de/proofbundle; a branch, a tag, or an unreleased commit fails before the gate runs.
- On a pull request the check reads the head of the pull request, not the merge commit, because the
  declaration names the tree of the commit that is pushed.

## Where the check stops

- **This template is not measured on GitHub Actions.** The Actions run of this check, including a merged
  pull request and a following waiver push, is a separate step still to be done; the template says NOT
  MEASURED here. It protects only with a required code owner review of `.proofbundle/` and of
  `.github/workflows/`, the job as a required status check, dismissal of stale approvals, and
  `require-declaration: true` in the caller. The CODEOWNERS template covers `/.proofbundle/`,
  `/.github/workflows/`, `/.github/actions/` and `/.github/CODEOWNERS`.
- CODEOWNERS protects a pull request only when it is already in effect on the branch the pull request
  targets. GitHub reads CODEOWNERS from the base branch, so a CODEOWNERS added or widened in the same pull
  request does not require the review for that pull request; the file must be merged into the base first.
- Dismissing stale approvals is a setting the repository must turn on; recommending it here is no statement
  that it is configured. The same holds for who may bypass the required review: a repository or
  organization admin, a user or team on a ruleset's bypass list, or a push that a branch protection rule
  does not apply to admins can merge without the code owner review. These exceptions are GitHub settings,
  not verified by this template.
- A pull request can change the workflow it runs under, including `require-declaration`, or add a workflow
  with a matching job name. The protection holds only with the review and dismissal rules above, and, where
  available, an organization ruleset that pins the required workflow (a `workflow_call` reusable workflow is
  not itself a ruleset trigger, so the caller must still run on the protected events). These GitHub settings
  are the repository's to configure and are not verified here.
- The gate code is taken from a `v*` release tag of b7n0de/proofbundle (`git tag --contains`), which allows
  an ancestor of a release tag and does not certify the SHA is itself the tagged commit.
- The check does not compare the evidence rules with an earlier state, as the gate does before a push
  (D20). In CI that comparison is the code owners' review of `.proofbundle/`.
- The check never fetches the repository under review and never signs. It needs network only to fetch the
  gate's tags and for uv to install the proofbundle version the plugin's server pins.
- The action pins are copied from proofbundle's own workflows. They were not re-checked against GitHub
  for this template.

## Running it locally

```sh
python plugins/proofbundle/hooks/proofbundle_gate.py ci-check --repo . --require-declaration true
```

## The done check in CI

The workflow's job `done` (input `done-check: true`) is the hard boundary of the user path "Claude says done"
(DECISIONS.md, D26). It runs the tests of the commit under review with a receipt, signed with a CI key, and runs
`proofbundle_gate.py done-check --at-commit` for the commit it checked out: exit 0 only when the receipt verifies
under the done policy at that commit, says that every test passed and names that commit and its tree, from a clean
run (`git_clean` true). The commit comes from the event (the head of a pull request, else the pushed commit), not
from HEAD: the test command runs the code under review, which can change the working tree or move HEAD, and a
receipt for anything but the commit's own tree fails (review 2026-10-09, F1). The job checks the commit out with
its whole history (`fetch-depth: 0`): an order that names paths is compared with the commit that declared it (D28),
and a checkout of one commit leaves that NOT MEASURED (review 2026-10-09, F4). Make the job a required status check,
like the job `evidence`.

```yaml
jobs:
  proofbundle:
    uses: ./.github/workflows/proofbundle-evidence.yml
    with:
      require-declaration: false
      proofbundle-ref: <the full commit SHA of b7n0de/proofbundle you reviewed>
      done-check: true
      done-test-command: python -m pytest -q
      done-proofbundle-version: "==<the release whose pytest plugin names the git state>"
    secrets:
      PROOFBUNDLE_DONE_KEY: ${{ secrets.PROOFBUNDLE_DONE_KEY }}
```

An order with several checks (D28) needs one receipt per check. The job names the folder the done check reads in
`PROOFBUNDLE_RECEIPT_DIR` (`done-check --receipt-dir`), and each check leaves `<id>.json` there; `PROOFBUNDLE_OUT`
names `tests.json`, the receipt of the one-check form, so the plain test command above needs nothing more. For an
order with the checks `unit` and `integration`, set `PROOFBUNDLE_OUT` per run and give each run exactly the check's
pytest arguments (no `-q`, an empty `PYTEST_ADDOPTS`):

```yaml
      done-test-command: >-
        PYTEST_ADDOPTS= PROOFBUNDLE_OUT="${PROOFBUNDLE_RECEIPT_DIR:?}/unit.json" python -m pytest tests/unit;
        PYTEST_ADDOPTS= PROOFBUNDLE_OUT="${PROOFBUNDLE_RECEIPT_DIR:?}/integration.json" python -m pytest tests/integration
```

Until review 2026-10-09 (F3) the job passed exactly one receipt with `--receipt`, so an order with two checks ended
in `gate_error`.

Where the receipt comes from is an owner choice:

| Option | What happens | Trade-off |
|---|---|---|
| A. Made in CI (built, recommended) | The job runs the tests on the checkout of the commit and signs with the CI key; the receipt never leaves the job | The tests run the code under review with the key file present, so a reviewer must read changes to the tests; GitHub passes no secret to a fork's pull request |
| B. Brought by the agent | The receipt the Stop hook accepted travels with the pull request and CI checks it | A committed receipt changes the tree it names, so it must travel outside the tree (an artifact, a comment, a separate ref); CI can check the key and the tree, but not where and how the run happened, nor which tests it selected: a run that leaves a failing test out gets a green receipt for the same tree |

The done policy pins the CI key (and, for the Stop hook, the developer's local test key). The receipt is
written to `$RUNNER_TEMP`, outside the checkout, and the job prints its sha256; upload it with an artifact
action you pin yourself if you want to keep it.

