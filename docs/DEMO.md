# Demo — see it work, then watch it fail

Three tiers, each copy-paste, each stating its offline guarantee. Every block ends with the
expected output so you can diff.

## Tier 0 — pip only (no checkout, no extras, no network)

The fastest way to see the whole trust story. Runs entirely in memory.

```bash
pip install proofbundle
proofbundle demo
```

Expected (exit code 0):

```
proofbundle offline demo — in memory, no files, no network

[PASS] honest receipt verifies  => OK

tamper matrix (each must be caught → verify FAILED):
  [caught] payload rewrite (passed:true→false)
  [caught] signature graft from another key
  [caught] public-key swap to attacker key
  [caught] Merkle root replacement
  [caught] leaf-index shift
  [caught] drop merkle.hash_alg (non-canonical)

[PASS] per-sample audit: challenged index N: honest opening OK=True, swapped-sample opening OK=False (must be False)

=> OK — every guarantee held
```

The command exits non-zero if *any* tamper verifies — so it is also a fail-closed smoke test.
`proofbundle demo --json` prints the same result machine-readably.

## Tier 1 — from a checkout, no optional extras

```bash
git clone https://github.com/b7n0de/proofbundle && cd proofbundle
pip install -e .
make tamper-demo        # the Tier-0 demo with an exit-code contract
make persample-demo     # the forced-random-sample audit walkthrough, offline
make examples           # runs every example that needs no optional extras
```

`make persample-demo` (expected tail):

```
receipt signed: accuracy 0.857000 over n=1000; samples root committed & signed
auditor challenges 20 random indices with a fresh nonce: [...]
  (catches 1% doctored samples with probability 18.2%)
[PASS] all 20 openings verify against the signed root
[PASS] swapped-sample opening is rejected
=> OK
```

### The reviewer's forced-random-sample check (real CLI)

```bash
# 1. Producer commits every sample and signs the root INTO the receipt (see examples/persample_audit.py).
#    The tree_secret stays with the producer; the receipt only carries {root_b64, n, leaf_alg}.

# 2. Auditor derives k indices from a FRESH nonce AFTER seeing the signed receipt — no grinding:
proofbundle audit-challenge "<samples_root_b64>" <n> <k> --nonce <>=32 hex chars> --json

# 3. Producer answers with an opening per index; auditor verifies each against the SIGNED root:
proofbundle verify-opening opening_<i>.json --root "<samples_root_b64>" --n <n> --json
#    A swapped or replayed sample → ok:false (the record's embedded idx must equal the proven position).
```

Running `audit-challenge` WITHOUT `--nonce` prints a warning: self-challenge mode is a sanity
check only — a producer could grind by re-salting. Real audits use a fresh auditor nonce or a
public randomness beacon.

## Tier 2 — full pipeline with real eval logs (optional extras)

```bash
pip install "proofbundle[eval,inspect]"
make full-demo          # inspect_ai mockllm + lm-eval dummy logs -> signed receipts -> verified
```

No network, no API key, no GPU: it turns genuine (committed, offline-generated) eval logs into
signed, Merkle-anchored receipts and verifies them.

## What a FAIL looks like

Any tamper — a flipped byte, a grafted signature, a swapped Merkle root, a stripped Key-Binding
JWT, a swapped sample — makes `verify` print the failing check name and exit non-zero:

```
[PASS] ed25519-signature: ...
[FAIL] merkle-inclusion: inclusion proof failed
=> FAILED
```

That is the whole point: an honest receipt is boring, and every dishonest one is loud.
