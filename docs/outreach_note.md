<!-- Draft outreach note (Linse 6). HUMAN decides whether/when to send. Factual, no marketing. -->

# Draft outreach — AISI inspect_ai / Arcadia Impact

Subject: a small offline verification layer for trustworthy eval results

Hi,

Your paper (arXiv:2507.06893) names an open gap — "a collaborative database of trusted evaluation
results with proper provenance tracking". I built a small, MIT-licensed, pure-Python tool that may be the missing
verification layer for it: **proofbundle** (github.com/b7n0de/proofbundle).

It turns an eval run into a signed, Merkle-anchored receipt that proves a stated threshold was met —
verifiable offline, from one file — while keeping the model and dataset as salted commitments (SD-JWT
selective disclosure, RFC 9901). It has a direct inspect_ai adapter (stable `read_eval_log`) and an
lm-evaluation-harness adapter, and an in-toto Statement v1 view.

It is deliberately narrow: it proves *passed against threshold*, not that the evaluation was well
designed. It does not compete with metadata aggregation (Every Eval Ever) or documentation taxonomies
(Eval Factsheets) — it is the signature + disclosure layer underneath them.

If a verifiable-receipt layer is useful to what you are building, I would welcome pointers on the format.

— Konrad

It runs fully offline — `make demo` turns a real mockllm `.eval` log into a signed receipt and verifies it, no network or GPU. I also saw inspect_evals PR #1610 (a SHA-256 attestation exporter) was closed as belonging a layer above the framework; proofbundle is that standalone layer and adds a signature, a Merkle anchor and selective disclosure over a bare hash.

(Draft — I will post and reply personally per the inspect_evals AI-use policy.)
