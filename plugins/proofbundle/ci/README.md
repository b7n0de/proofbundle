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
