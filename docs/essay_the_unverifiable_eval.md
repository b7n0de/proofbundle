# You cannot verify an AI evaluation result

> Draft for the blog, then dev.to with a canonical tag. Publish after v0.4 ships, so it
> references a real feature. Keep it honest: no adoption claims, no superlatives. Before
> publishing, verify and link the two factual claims below.

Every week a model ships with a number attached. Passed the safety suite. Ninety-two percent on the benchmark. Refuses the bad prompt. We read these numbers and move on.

Here is the uncomfortable part. You cannot check any of them. The number is asserted, not proven. To recompute it you would need the model weights and the exact dataset, which are usually secret. So the claim rests entirely on trust in whoever published it.

We solved this shape of problem once already, for software builds. Sigstore, SLSA and in-toto let you verify where an artifact came from without trusting the person who handed it to you. But that machinery stops at the build. It says nothing about whether an evaluation result is real. The [OpenSSF Model Signing spec](https://github.com/ossf/model-signing-spec) states plainly that it does not cover quality or evaluation. And the people running frontier evaluations feel the gap: the maintainers of inspect_evals (Arcadia Impact, UK-AISI-funded) have [publicly called](https://arxiv.org/pdf/2507.06893) for a database of trustworthy evaluation results with proper provenance tracking.

So the tooling exists, the demand exists, and nobody has connected them.

The missing piece is small. Take the same primitives, an Ed25519 signature over a canonical claim, an RFC 6962 Merkle anchor so the claim sits in a tamper-evident log, and salted commitments to the identifiers so they cannot be guessed. Emit a receipt that says exactly one thing, suite S scored over threshold T, and carries only salted commitments to the model and dataset identifiers, never the model or the data. A third party can then verify that the threshold was met, offline, from one file, without ever seeing the weights or the test set.

That is what I am building. proofbundle is a small, pure Python tool that verifies and emits these receipts. No server, no daemon, no custom cryptography. The verifier shipped first so it could be reviewed on its own, the emitter followed, and the eval receipt is the point of the whole exercise.

It is deliberately narrow. A receipt proves that a stated threshold was met on a stated suite. It does not prove the evaluation was well designed, or that the suite measures what it claims. Those are human judgements. What it removes is the need to simply trust the number.

If you work on AI evaluation, model cards, or compliance evidence under the EU AI Act, this is the primitive under your feet. The format is specified, the code is MIT, and I would rather get the design wrong in public than right in private.

Repo and spec, github.com/b7n0de/proofbundle.

---

Facts to verify before publishing:

1. OpenSSF Model Signing explicitly does **not** cover eval quality — <https://github.com/ossf/model-signing-spec>.
2. UK AISI publicly calls for provenance for trustworthy eval results — <https://arxiv.org/pdf/2507.06893>.

SD-JWT is [RFC 9901](https://datatracker.ietf.org/doc/rfc9901/) (November 2025); SD-JWT VC remains an IETF draft.
