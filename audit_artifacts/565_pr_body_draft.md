# DRAFT — in-toto/attestation spec-only PR body (eval-result/v0.1)

> §12 Versand-Regel: Der Agent öffnet diesen PR NICHT. Dieser Text wird als
> `audit_artifacts/565_pr_body_draft.md` im pb-Repo abgelegt; geöffnet wird erst nach expliziter
> Owner-Freigabe. Vorlage unten auf Englisch (Upstream-Kommunikation).

---

Title: `predicates: add eval-result/v0.1 (AI/ML evaluation results)`

## Body

This adds the `eval-result` predicate proposed and discussed in #565: a threshold-based,
privacy-preserving attestation of an ML evaluation result.

Following the new-predicate guidelines, this PR contains **only** the spec file
(`spec/predicates/eval-result.md`) and the README table row. The protobuf definition and a CUE
example are prepared and follow as a separate PR once the spec lands (the same split SVR used:
spec #470, proto #519, README #537).

Scope boundary (pinned in #565's non-goals after community review): `eval-result` is **metric
evidence only** — not agent-decision attestation, not action authorization, not a policy verdict,
not an action outcome. The decision-side record is a separate predicate
(`decision-receipt`, vendored downstream), deliberately kept out of this proposal.

What exists today, verifiable:

- A working emitter/verifier (reference implementation: proofbundle, PyPI, `proofbundle intoto`),
  emitting the vendor-namespaced `https://b7n0de.com/attestation/eval-result/v0.1` with a
  documented migration to the `in-toto.io` URI on registration.
- An **independent second implementation** of the canonical statement/content-root path
  (MarkovianProtocol/audit-anchor: content roots recomputed from the RFC 8785 canonical statement
  bytes, byte-identical JCS, externally anchored) — see the #565 thread.
- Conformance vectors (positive + negative) in the reference implementation's `conformance/`
  corpus.

The predicate deliberately does not claim semantic truth, fairness, safety, or generalization of
the result — the Non-claims section is part of the spec text.

DCO signed-off; happy to iterate on field naming or structure per maintainer preference.

---

## Checkliste vor Owner-Freigabe (Agent füllt aus, Owner entscheidet)

- [ ] Maintainer-Signal in #565 vorhanden ODER Owner entscheidet bewusst "PR ohne Vorab-Zusage"
      (Guidelines: "your predicate is yours" — prozesskonform)
- [ ] Spec-Datei ist ITE-9/template-konform (docs/upstream/eval-result.md, Stand 2026-07-10)
- [ ] README-Zeile vorbereitet
- [ ] .proto + CUE als Follow-up-PR-Material im pb-Repo abgelegt
- [ ] DCO-Sign-off konfiguriert (kraxo@b7n0de.com)
