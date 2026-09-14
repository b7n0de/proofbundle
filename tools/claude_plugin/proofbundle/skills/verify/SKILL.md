---
name: verify
description: Verify a proofbundle receipt offline - checks the DSSE signature, the subject binding, and reports the honest strength. Use when the user asks to verify, check, or validate a proofbundle receipt, an agent-review receipt, or a .receipt.json file.
---

# Verify a proofbundle receipt

Verify a receipt **offline**, against proofbundle **6.0.0** (tag `v6.0.0`). Report what the
verifier says, never what a field inside the receipt claims about itself.

## The one rule that matters

A receipt carries a `strength` field. **Do not read it and report it.** A receipt is a statement
about itself; asking it whether it is valid answers a different question than the one the user
asked. Run the verifier and report its verdict.

## Steps

1. Locate the receipt file the user means (`*.receipt.json`, a DSSE envelope).
2. Run the verifier pinned to 6.0.0.
3. Supply the **expected subject digest**. Without it the verifier answers `ok: false` with the
   reason that nothing establishes the receipt belongs to the object in front of you - which is
   correct, not a failure. A valid receipt for a *different* subject passes every other check.
4. Report `ok`, `crypto_ok`, the subject binding, and any `reason_codes`, each with its measured
   value.

```bash
PYTHONPATH=src python -c "
import json, sys
from proofbundle import agent_review as ar
env = json.load(open(sys.argv[1]))
pred = json.loads(__import__('base64').b64decode(env['payload']))['predicate']
r = ar.verify_agent_review(env, bytes.fromhex(sys.argv[2]),
                           expected_subject_digest=ar._subject_digest(pred))
print(json.dumps({k: r[k] for k in ('ok','crypto_ok','subject_binding_ok',
                                    'expected_subject_match','reason_codes')}, indent=2))
" <receipt.json> <public-key-hex>
```

## Reporting

State the verdict in one line, then the measured fields. If `ok` is false, name the reason code
rather than paraphrasing it. If the public key was not supplied by the user, say that the run
checked internal consistency only - do not call that a passed verification.

Honest limits, always worth saying: this verifies a signature and a binding. It does not say the
reviewed work is correct, and it is not a security audit.
