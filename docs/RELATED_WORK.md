# Related work

The canonical related-work write-up for proofbundle, kept in one place so the README, the next
Technical Note version, and the JOSS paper draft all draw from the same honest text instead of three
drifting copies. Every citation here was checked against its arXiv full text on 2026-07-17 (dates and
authors below are the verified submission facts, not a secondary summary).

proofbundle sits in an active and growing field: verifiable, tamper-evident evidence for AI work. The
message is complementarity, not superiority. Neighbouring work validates that the problem is real; a
receipt is one released, offline, eval-shaped answer within it, and it is honest about the line it
does not cross.

## Closest neighbour: AuditWeave

**AuditWeave** ([arXiv 2607.09682](https://arxiv.org/abs/2607.09682), Vimal Nakrani, submitted
14 June 2026; PyPI `auditweave`, CC BY 4.0) is a lightweight, dependency-free Python library that
records AI-assisted and data-transformation workflow steps into a hash-chained, tamper-evident
evidence ledger, and lets an auditor navigate from a conclusion to the evidence behind it.

Honest differentiation, one line: AuditWeave is a hash-chained, auditor-navigable evidence ledger for
whole workflows; proofbundle is a signed (Ed25519) plus RFC 6962 Merkle receipt for a single eval or
decision result, adds an external time anchor and offline third-party verification, and carries a
typed relation/v0.1 lineage between receipts. The two are complementary: one weaves the trail across
a workflow, the other makes each result a portable, independently checkable receipt. No value
judgement about the other work is made or implied.

The auditor-navigation idea (start from a verdict, walk to its ordered evidence) is the AuditWeave
lesson already reflected on our side in the reviewer readiness pack, `docs/readiness_pack/`
(Fundament F5, `GO_OWNER_PB_ROADMAP_FRONTLOAD_20260716`). It is referenced here so it is not built a
second time.

## Adjacent audit-trail and tamper-evident-logging work

One line each, only where the work substantively touches the same problem:

- **Attestable Audits** ([arXiv 2506.23706](https://arxiv.org/abs/2506.23706), Schnabl, Hugenroth,
  Marino, Beresford, 30 June 2025): TEE-verified AI safety audits. Complementary on execution, a
  receipt proves authorship and integrity, not that the computation ran correctly. This neighbour
  also has a full row in the README table, so it is not repeated there.
- **From Runtime Records to Legal Findings** ([arXiv 2607.00941](https://arxiv.org/abs/2607.00941),
  Jeroen Janssen, 1 July 2026): an evidentiary-adequacy criterion for when a runtime record can
  support a legal finding about agentic AI oversight.
- **Audit Trails for Accountability in LLMs** ([arXiv 2601.20727](https://arxiv.org/abs/2601.20727),
  Ojewale, Suresh, Venkatasubramanian, 28 January 2026): a tamper-evident, context-rich ledger of
  LLM lifecycle events linking technical and governance records.
- **Who Audits the Auditor?** ([arXiv 2604.22096](https://arxiv.org/abs/2604.22096), Zhaohui Wang,
  23 April 2026): blockchain-anchored, tamper-resistant audit trails so a privileged operator cannot
  rewrite machine-learning decision records.
- **Rethinking Tamper-Evident Logging** ([arXiv 2509.03821](https://arxiv.org/abs/2509.03821), Zhao,
  Shoaib, Hoang, Ul Hassan, 4 September 2025): a high-performance, co-designed systems approach (eBPF)
  to fine-grained tamper-evident logging.

The pattern across these is convergence: verifiable, tamper-evident evidence for AI is an active area,
and proofbundle's place in it is the released, offline, eval-shaped receipt with an external anchor
and typed lineage, complementary to each.

## Already covered in the README neighbour table

The README section [Where it sits in the research neighbourhood](../README.md#how-it-fits-together)
covers K-Veritas, Attestable Audits, BenchJack, Evaluation Cards, and the stable in-toto / Sigstore /
SCITT / OpenSSF standards. Those are not repeated here.

## Reuse: the JOSS paper and the next Technical Note

This file is the filed building block for two future documents. Neither is edited now on purpose:

- **JOSS paper** (`paper.md`, submission preparation from 01/2027): the "State of the field" section
  can absorb the AuditWeave paragraph and the adjacent cluster from here. Adding the matching entries
  to `paper.bib` is deferred to JOSS-writing time so the bibliography stays in step with the paper.
- **Technical Note** (next version only): the same related-work paragraph is pulled into the Note in
  its LaTeX style at the next Note release. The 3.2.3 Note is not republished only for this. Until
  then the public positioning lives in the README and in this file.

## Standing rule

New neighbouring work is watched, cited, and honestly differentiated, never disparaged. Priority is
represented only through dated public records (see [PRIORITY_RECORD.md](PRIORITY_RECORD.md)), not as a
claim against any named work.
