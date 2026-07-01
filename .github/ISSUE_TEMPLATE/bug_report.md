---
name: Bug report
about: Something the verifier gets wrong, or a crash
title: "[bug] "
labels: bug
---

**What happened**
A clear description of the bug.

**Bundle / input**
If possible, attach a minimal `bundle.json` that reproduces it (redact any real
payload if needed — the verifier treats the payload as opaque bytes).

**Steps to reproduce**
```
proofbundle verify path/to/bundle.json
```

**Expected vs actual**
What you expected, and what you got (paste the `[PASS]/[FAIL]` output).

**Environment**
- proofbundle version:
- Python version:
- OS:
