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

Then make the job a required status check of the branch.

- `require-declaration` has no default. The caller decides, in a file CODEOWNERS covers.
- `proofbundle-ref` must be a full 40-character commit SHA. A branch or a tag fails the first step.
- On a pull request the check reads the head of the pull request, not the merge commit, because the
  declaration names the tree of the commit that is pushed.

## Where the check stops

- A pull request can change the workflow it runs under, including `require-declaration`. The check
  therefore protects only together with the CODEOWNERS template and a branch ruleset or branch
  protection that requires a review from code owners.
- The check does not compare the evidence rules with an earlier state, as the gate does before a push
  (D20). In CI that comparison is the code owners' review of `.proofbundle/`.
- The check never fetches and never signs. It needs network only for uv to install the proofbundle
  version the plugin's server pins.
- The action pins are copied from proofbundle's own workflows. They were not re-checked against GitHub
  for this template.

## Running it locally

```sh
python plugins/proofbundle/hooks/proofbundle_gate.py ci-check --repo . --require-declaration true
```
