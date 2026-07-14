# Baseline 3.1.3 (re-verified 2026-07-14)

The 3.2.0 implementation prompt's §0 status table is a hypothesis register, not a blank check — it
says "vor Weiterarbeit erneut prüfen". This file records the re-verification of that table against
the actual current state, with the command evidence for each row. No claim without a check.

## Verified baseline

| Item | Prompt §0 premise (from 14.07 morning report) | Re-verified state (2026-07-14) | Evidence |
|---|---|---|---|
| PyPI latest | 3.1.3, Classifier `4 - Beta` | **3.1.3** (unchanged) | `pypi.org/pypi/proofbundle/3.1.3/json` resolves; 2 release files |
| Website product page | on **3.1.0**, needs sync to 3.1.3 | **already on 3.1.3** (premise stale) | product/deep pages label 3.1.3; `v3.2.0` appears only as "planned/target, not part of the PyPI package today" (no premature version claim) |
| Website SSOT + drift gate | P0-F open | **present + green** | release-manifest SSOT `proofbundle_facts.json` (version 3.1.3, test_count 989 = the real 3.1.3 count); homepage-sync doctor PASS, 0 findings; CI drift gate wired |
| GitHub Releases | ends at `v2.0.0b3`, Latest-flag `v1.9.2` | **v3.0.0 … v3.1.3 exist, Latest = v3.1.3** (premise stale) | `gh release list` shows `v3.1.3  Latest` |
| PEP-740 attestation of 3.1.3 | not cross-checked | **present** — an in-toto `Statement/v1` + Sigstore signature | `pypi.org/integrity/proofbundle/3.1.3/proofbundle-3.1.3-py3-none-any.whl/provenance` returns an `attestation_bundles` payload whose statement subject is `proofbundle-3.1.3-py3-none-any…` (note: the JSON-API `provenance` field reads `null`, which is misleading — the integrity endpoint is authoritative) |

## Conclusion

TEIL 1 of the 3.2.0 prompt (G1 website + SSOT + drift gate, G2 GitHub releases Latest = v3.1.3, G3
PEP-740 attestation) is, on re-verification, **already satisfied** — prior release cycles closed it.
The 3.1.3 line is a coherent, published baseline: PyPI = Website = GitHub-Latest = SPEC, real test
count 989, attested. 3.2.0 work (the receipt-chain O-item predicates + the release-review hardening +
the independent cross-implementation verifier) builds forward from here; nothing in 3.2.0 has been
tagged or published (that remains a human-release action).
