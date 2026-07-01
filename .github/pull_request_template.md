## What this changes

Briefly describe the change and why.

## Checklist

- [ ] `python -m unittest discover -s tests` is green
- [ ] `ruff check .` is clean
- [ ] No new runtime dependency (dev dependencies are fine)
- [ ] No own cryptography — signatures via `cryptography`, Merkle via the stdlib
- [ ] Scope stays on the verifier and bundle emitter (the eval-receipt emitter is a separate v0.3 roadmap item)
- [ ] Docs / README updated if behavior changed
