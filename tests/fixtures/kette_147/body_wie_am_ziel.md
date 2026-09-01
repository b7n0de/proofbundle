**Two things from our side, both checkable.**

**`proofbundle 5.0.0` is on PyPI since 2026-08-27.** That was the condition I named on 26 August, so this is a discharge rather than an announcement.

**R6 is now shipped rather than stated.** The profile says that claiming it means shipping the executable counter-probes plus positive controls at 100 percent detection, and that a profile claim with no probes attached is the counter-probe to that rule. Until now my own claim had no probes attached. The profile is `proofbundle/receipt-envelope-profile/v0.1`, published at [RECEIPT_ENVELOPE_PROFILE.md](https://github.com/b7n0de/proofbundle/blob/27a84db3c6dca99d0deb6199b84306df1a035898/docs/RECEIPT_ENVELOPE_PROFILE.md) and archived at [10.5281/zenodo.22209671](https://doi.org/10.5281/zenodo.22209671), and the probes are at [conformance/envelope_profile](https://github.com/b7n0de/proofbundle/tree/27a84db3c6dca99d0deb6199b84306df1a035898/conformance/envelope_profile). They run against any envelope, ours included. Our own emit path sits in the positive controls, and where it fails it is reported as failing. To be precise about where they are: the profile and the vectors ship in the sdist and live in the repository; the wheel carries neither, which is deliberate because the wheel is the import package. They cover R1 to R4. R5 states its requirement and points at the IETF work rather than shipping a probe, by decision.

On R1, your reading matches mine, and the next round is a named commit either way. Nothing to add from here until that commit exists.

On the pairing pass, yes. Bound to your named commit, because there is nothing to pair against before it. I will run the same probes against yours that I ran against `397ae3ad` and post the result here, pass or fail, in the same shape.

One small ask, and it is a courtesy rather than a claim. Four of the requirements in this profile came out of this measurement series. R1 from the canonicalisation thread, R2 and R3 from E1 and E2, R4 from the key-resolution probes. Your README documents them as design properties of the package, which they now are. A line pointing back to this issue would let a reader arriving at the README see where they were worked out. I will do the same in reverse and link your implementation from ours.

**Two conditions on anything shared, and they are the two I set out on 26 August.**

The trust anchor stays the emitter's field. No shared artifact carries any party's root as a default, `did:web:csoai.org` and ours alike. Your comment says the same. I am restating it because a default in code outweighs a sentence in prose, and `verify()` currently defaults to yours.

The profile keeps its name and its home. It lives in this repository, it is versioned, and conformance is demonstrated by running the probes and posting the result, not negotiated into a third name. The profile creates no assessing party. Conformance is shown, never conferred, and no party is appointed to judge another's. Two implementations of one named profile is a stronger result for both of us than one merged format with no owner.

Thread ordering as you have it, with one change on my side. In #4413 I am withdrawing the narrow yes/no rather than repeating it, because that repository's own contribution rules already answer it; the issue itself stays open. Time stays in #7, this issue stays the envelope.

Measurement, not certification.

Prepared with AI agent involvement, reviewed and submitted under human oversight.

<!-- proofbundle:agent-review:begin -->
**Agent review receipt** · Tier 1, selfDeclared
[proofbundle_147_comment.r2](https://github.com/b7n0de/proofbundle/blob/47c3164791033eab7c92196bbf47ada58f233d88/receipts/agent_review/proofbundle_147_comment.r2.receipt.json) · [transparency log entry](https://log.markovianprotocol.com/leaf/7731)
<sub><code>sha256:179aa1cd79558dbec66d8cbf226c7f6740863e50627b2d83c9b614902efb039c</code></sub>
<!-- proofbundle:agent-review:end -->
