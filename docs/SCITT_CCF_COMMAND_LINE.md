# The scitt-ccf command line

`proofbundle scitt-ccf` runs the `scitt-ccf/v1` reader of ADR 0009 (`proofbundle.scitt_ccf`) on files. It has two
subcommands: `verify-statement` calls `verify_transparent_statement`, and `verify-consistency` calls
`verify_consistency_receipt`. Each prints the verdict of that function, as text or with `--json` as the
function's `to_dict()` beside the exit code and the trust that was given.

Status: EXPERIMENTAL, like the reader. It needs the `[scitt]` extra; without it both subcommands exit 2 with the
status `no_lib`. The reader follows draft-ietf-scitt-receipts-ccf-profile-06, and its rules, limits and statuses are
the ones ADR 0009 and the module docstring of `proofbundle.scitt_ccf` state. This page describes only what the
command line adds.

## Where trust comes from

Only from the options. Nothing is fetched, and nothing inside the evidence is trust: a kid, a key or a certificate
in a statement or receipt only selects among the keys you gave.

| Option | What it is | Passed to the reader as |
|---|---|---|
| `--issuer` | the service whose receipts you trust, compared exactly with the CWT `iss` of a receipt | the key of `rp_trust["scitt_ccf_services"]` |
| `--service-keys FILE` | that service's keys as a COSE_KeySet in CBOR, as `/.well-known/scitt-keys` serves them | `load_cose_keyset` of the file |
| `--statement-key FILE` | a key of the statement signer as a DER SubjectPublicKeyInfo (EC P-256, EC P-384 or RSA), repeatable | `rp_trust["scitt_statement_keys"]` |
| `--expected-digest HEX` | the SHA-256 digest the statement's hash envelope must carry, the digest of the artifact you hold | `canonical_root` |
| `--older-root HEX` | a root you have already verified, for instance the Merkle root of a confirmed inclusion receipt | `older_root` |
| `--older-issuer` | the issuer of the receipt that verified `--older-root`, by default `--issuer` | `older_issuer` |
| `--older-size M`, `--newer-size N` | the two tree sizes, from a source you trust independently of the receipt | `older_size`, `newer_size` |

Trust material the reader would only ignore is refused before any verdict, with exit 2: an empty issuer, a key set
that is not CBOR or holds no EC2 key on P-256 or P-384, a statement key the reader does not verify with, and more
than 64 statement keys. Without this refusal the verdict would say `needs_rp_trust` about trust you did give. A
digest or root is 64 hex digits; the white space around it is stripped, and none is taken inside it.

## Exit codes

The command maps each status of the reader to one of four exit codes, in the classes `verify-trace` and
`verify-sigstore` use. `tests/test_cli_scitt_ccf.py` holds both tables equal to the reader's statuses.

| Exit | Meaning | verify-statement | verify-consistency |
|---|---|---|---|
| 0 | every check of the profile held | `confirmed` | `confirmed`, `confirmed_without_tree_sizes` |
| 1 | the evidence does not verify against what you gave | `outside_profile`, `unbound`, `statement_signature_invalid`, `root_mismatch`, `signature_invalid`, `receipt_not_bound` | `outside_profile`, every `consistency_*` status, `signature_invalid` |
| 2 | unreadable under the profile, an option or file that cannot be used, or no `[scitt]` extra | `malformed`, `no_lib` | `malformed`, `no_lib` |
| 3 | sound evidence, but none of the trust you gave matches it | `needs_rp_trust` | `needs_rp_trust` |

`confirmed_without_tree_sizes` is exit 0, as `verify` exits 0 without `--policy`: every check of Figure 9 held,
and 0 < m < n was not asked for. The text output says `TREE-SIZES: NOT_CHECKED`, and the JSON status names it. Give
both `--older-size` and `--newer-size` to get `confirmed`.

## Examples

With the committed vectors of a local scitt-ccf-ledger run, written out to files first:

```
proofbundle scitt-ccf verify-statement statement.cose \
    --expected-digest df6557c0af226ef3e18e2694c7d6b153343495bc9b6f459f6858e7276ea0fac9 \
    --issuer 127.0.0.1:8000 --service-keys scitt-keys.cbor --statement-key signer.der

proofbundle scitt-ccf verify-consistency consistency-receipt.cose \
    --older-root 16b49c67c4943baaeec85e2d7ac4cd1f9dbbab050cdd2480c8b1061c162430e2 \
    --issuer 127.0.0.1:8000 --service-keys ledger-keys.cbor \
    --older-size 19 --newer-size 24 --json
```

`statement.cose`, `scitt-keys.cbor` and `signer.der` are `transparent_statement_b64`, `service_keyset_b64` and
`statement_signer_spki_b64` of `local_ledger_control.json`, decoded. `consistency-receipt.cose` and
`ledger-keys.cbor` are `consistency_receipt_b64` and `service_keyset_b64` of `local_ledger_consistency.json`: that
vector comes from another run of the ledger, with its own service key, and under the key set of the first vector
the second command ends with `needs_rp_trust`, exit 3. As written, both commands end with `confirmed`, exit 0.

`tests/test_cli_scitt_ccf.py` builds these files from `tests/fixtures/scitt_ccf/local_ledger_control.json` and
`local_ledger_consistency.json` and runs each exit code.

## What a pass does not say

`verify-statement` exit 0 says that the statement carries the digest you gave, that it is signed by a statement key
you gave, and that a receipt of the service you named binds it under that service's key. It does not say that the
statement's content is true, and the receipt's `iat` is the service's own statement of time, reported as
`receipt_iat`, not a trusted time.

`verify-consistency` exit 0 says that at least one proof recomputes the older root you gave, that every proof
computes the same newer root, and that the service you named signed that newer root under its key. It says nothing
about the statements in either tree, and the tree sizes are only ever yours: the draft says a verifier that needs
them "MUST obtain them from a source it trusts independently of the receipt" (-06, 7.3).
