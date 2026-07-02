---
name: External review / audit finding
about: Report a security, cryptographic, or scope-honesty finding from an external review
title: "[review] "
labels: external-review
---

<!-- Thank you for trying to break proofbundle. See docs/REVIEWERS.md for the 30-minute audit path.
     For a SECURITY vulnerability (a fail-open, a verifying tamper), please use the private advisory
     in SECURITY.md instead of a public issue. -->

## What kind of finding
- [ ] Fail-open / verifying tamper (a bad receipt that verifies OK) — **use SECURITY.md if exploitable**
- [ ] Guarantee holds on emit path but not on verify path
- [ ] Scope overclaim (docs promise more than the code proves)
- [ ] Spec ambiguity / encoding ambiguity
- [ ] Interop / standards inaccuracy
- [ ] Other

## Evidence
<!-- file:line, a quoted hunk, or a reproducing transcript. Concrete beats general. -->

## Reproduction
```
# commands + expected vs observed. `proofbundle demo` and the make targets are good starting points.
```

## Environment
- proofbundle version:
- Python version:
- `cryptography` version:
- OS:

## Suggested fix (optional)
<!-- a patch sketch, a test name, or a doc wording — whatever you have. -->
