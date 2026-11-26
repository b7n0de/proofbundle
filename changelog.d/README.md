# CHANGELOG fragments

A pull request that changes what a user of proofbundle sees adds one fragment here instead of
writing under `## [Unreleased]` in `CHANGELOG.md`. Two pull requests then never edit the same
lines, so landing one does not make the other conflict.

A fragment is one file named `<stem>.<section>.md`:

- `<stem>` is any unique name of lower-case letters, digits and hyphens, at most 64 characters,
  for example the slug of the branch or the issue number.
- `<section>` is one of `security`, `added`, `changed`, `deprecated`, `removed`, `fixed` and
  names the `### Section` the lines belong to.
- The content is exactly the lines the pull request would otherwise write under that section,
  starting with `- `, with LF line ends, no empty line and no heading.

A pull request with entries in two sections adds two files with the same stem.

`python3 scripts/changelog_fragments.py check` checks every file here and exits 1 on a finding.
At the release cut, `python3 scripts/changelog_fragments.py collect` moves all fragments under
`## [Unreleased]` in `CHANGELOG.md`, by section and then by file name, and removes them.
Writing directly under `## [Unreleased]` stays valid; every check accepts either form.
