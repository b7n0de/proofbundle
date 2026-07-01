# Predicate type — `https://b7n0de.com/proofbundle/eval-receipt/v0.1`

A self-hosted in-toto **predicate type** for an eval receipt. A self-hosted `predicateType` URI is fully
[in-toto Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md)-conform and
the right choice for a solo v0.x — no official in-toto/attestation PR is needed. The URI must uniquely
identify the predicate; it need not resolve.

`proofbundle.intoto.to_intoto_statement(claim, root_b64=…, harness=…)` produces the statement.

## Honest digest semantics (important)

The `subject.digest` is a **salted commitment to the model identifier**, NOT the content hash of an
artifact. Placing it under the standard `sha256` key would suggest an artifact hash and mislead generic
in-toto verifiers. in-toto permits arbitrary digest keys, so proofbundle uses a unique custom key:

```json
"subject": [{ "name": "model-id-commitment",
              "digest": { "proofbundleModelCommitV1": "<hex of model_id_commit>" } }]
```

The same note is mirrored in `predicate.subject_digest_note`. Full artifact digests (under `sha256`) come
only once a model artifact exists — deferred.

## Predicate shape

`verifier` (proofbundle id), `evaluatedAt` (RFC 3339), `suite`, optional `harness` (name+version),
`claims` (metric/comparator/threshold/passed — copied from the receipt, not re-derived), `datasetCommit`,
and `receipt` (`schema` + `root_b64`, binding the statement to the signed bundle). Model, weights and data
never appear in plaintext. The statement validates against the official in-toto Statement-v1 JSON schema
(`schemas/in_toto_statement_v1.schema.json`, tested via jsonschema).
