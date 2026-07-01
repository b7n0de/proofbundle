## What this changes

Briefly describe the change and why.

## Checklist

- [ ] `python -m unittest discover -s tests` is green
- [ ] `ruff check .` is clean
- [ ] No new runtime dependency (dev dependencies are fine)
- [ ] No own cryptography — signatures via `cryptography`, Merkle via the stdlib
- [ ] Scope stays coherent with the layered design (core verifier + emitter + eval receipts, all shipped)
- [ ] Docs / README updated if behavior changed
