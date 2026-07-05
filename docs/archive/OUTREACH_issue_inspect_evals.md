<!-- DRAFT of an inspect_evals GitHub issue. The HUMAN posts it and writes every reply personally —
     inspect_evals' AI-Use policy requires agent-opened PRs to be drafts and human-written replies.
     This file is a draft for review only. Confirm inspect_evals uses Issues (not a Discussions tab) first. -->

# Draft issue — a standalone, cryptographic eval-receipt layer for provenance tracking

Your paper *Inspect Evals* ([arXiv:2507.06893](https://arxiv.org/html/2507.06893), Future Directions)
names an open need:

> a collaborative database of trusted evaluation results with proper provenance tracking

and, relatedly, *a centralized, trusted protocol for maintaining and accessing private test sets*.

I built a small, MIT-licensed, pure-Python tool that may be the verification layer for that:
**proofbundle** (github.com/b7n0de/proofbundle, on PyPI).

I've read the discussion on
[PR #1610](https://github.com/UKGovernmentBEIS/inspect_evals/pull/1610) (a third-party SHA-256 attestation
exporter), where the recommendation was to build the canonical attestation format as a standalone,
versioned spec + reference implementation in its own repo and ship an inspect_evals adapter later — and
where a bare hash's added value over just keeping the log was reasonably questioned. That is exactly the
shape proofbundle already takes, and it goes beyond a hash: an **Ed25519 signature**, an **RFC 6962 Merkle
anchor**, and **SD-JWT (RFC 9901) selective disclosure**, so a holder can prove *a threshold was met* while
withholding the exact score and keeping the model and dataset as salted commitments. It reads inspect_ai
logs via the stable `read_eval_log` API (no fork of your code) and emits an in-toto Statement v1 aligned to
the generic `test-result/v0.1` predicate.

I'm aware of related work in that thread — [ValiChord](https://github.com/topeuph-ai) explores a
Holochain-based, peer-to-peer validation network with rich "Harmony Records". proofbundle deliberately
takes the opposite, minimal shape: one portable JSON file, offline-verifiable with no network or
distributed substrate, built on off-the-shelf standards (in-toto, SD-JWT, RFC 6962) rather than a new
protocol. The two are complementary points on the spectrum, not the same thing.

It runs fully offline: `make demo` (no network, API key or GPU) takes a real `mockllm/model` `.eval` log,
turns it into a signed receipt, and verifies it to `=> OK`
([demo](https://github.com/b7n0de/proofbundle#demo--a-real-eval-log-to-a-verified-receipt-offline)).

Honest scope: it attests authenticity + integrity of a *claimed* result, not the correctness of the
computation (that is what TEE audits target) — so it complements, not replaces, your evaluation work.

**One question:** would an inspect_ai-log → in-toto-`test-result`-aligned receipt exporter, shipped as an
*optional external* library (not in inspect_evals itself), be useful to the trusted-results database you
describe? Happy to align field names with your schema.
