# Experimental: the TEE-attestation bridge (v2.0 preview)

> **Preview / unstable.** Everything here lives under `proofbundle.experimental` and the
> `[experimental]` install extra. Its API and wire format may change or be removed in any release
> without a deprecation cycle. It is not imported by the stable core.
> `pip install "proofbundle[experimental]"` (the extra ships with normal releases since the 2.0.0
> final; no `--pre` needed).

## What it's for

A software-only receipt proves **authorship + integrity** — who signed these bytes, and that
nothing changed. It cannot prove the **computation ran untampered**. A Trusted Execution
Environment (Intel TDX, an NVIDIA confidential-computing GPU) can attest exactly that. This bridge
lets a receipt's `assurance_level = enclave_attested` become something a relying party can actually
check, offline and vendor-neutral.

## The trust chain (and where proofbundle sits in it)

proofbundle follows the IETF **RATS architecture (RFC 9334), Passport model**:

```
enclave runs the eval, puts the receipt binding in the hardware quote's user-data
        │  (raw Evidence: Intel TDX DCAP quote / NVIDIA GPU attestation report)
        ▼
   RATS Verifier  ── appraises the raw Evidence out of band (vendor libs, live collateral, TCB policy)
        │           and issues a signed Attestation Result (an EAT, RFC 9711)
        ▼
   proofbundle    ── verifies the Attestation Result OFFLINE:  <-- this module
        • the EAT signature under the Verifier's key (a supplied trust anchor)
        • eat_nonce == enclave_binding_for(receipt)  (it's about THIS receipt)
        • eat_profile matches, if you pin one
        • reports the trustworthiness tier verbatim
```

**proofbundle deliberately does NOT parse or appraise raw hardware evidence.** Appraising a TDX
quote or a GPU report needs vendor tooling, live collateral (PCK certs, RIM bundles, CRLs) and TCB
policy — that is the Verifier's job. proofbundle checks the last two links of the chain (the
Verifier's signature and the receipt binding); the first link — *do you trust this Verifier's key,
and is its appraisal sound* — is your trust anchor, exactly like the log/witness/status keys in
[TRUST_ANCHORS.md](TRUST_ANCHORS.md).

## Wire format

The Attestation Result is an **EAT (Entity Attestation Token, RFC 9711)** in its JSON/JWS encoding,
signed with **EdDSA** (no new dependency). Claims:

| Claim | Meaning |
|---|---|
| `eat_nonce` (RFC 9711 §4.1) | the binding: MUST equal `enclave_binding_for(bundle)` = base64url SHA-256 over the receipt's exact signed payload. In production the enclave places this in the quote user-data (TDX `REPORTDATA` / GPU report nonce) at run time. |
| `eat_profile` (§4.3.2) | a profile URI identifying appraisal semantics; a relying party MAY pin one |
| `ueid` | the attested entity/enclave id — reported, not interpreted |
| `tier` | the Verifier's trustworthiness tier (this preview's stand-in for AR4SI/EAR, still IETF drafts) — REPORTED verbatim, never interpreted as a guarantee |
| `iat` / `exp` | freshness — reported, judged only when the caller passes `now` (offline verifier, no trusted clock) |

## Use

```python
import warnings
from proofbundle.experimental.enclave import enclave_binding_for, verify_enclave_attestation

# the value the enclave must place in its quote user-data when running the eval:
binding = enclave_binding_for(receipt_bundle)   # base64url sha256 of the signed payload

# later, given a Verifier-signed EAT + the Verifier's public key:
res = verify_enclave_attestation(eat_jws, verifier_pubkey=verifier_key,
                                 expected_binding=binding,
                                 expected_profile="https://…/eat-profile/tdx-gpu/v1")
res["ok"]      # signature + typ/alg + binding all held
res["tier"]    # the Verifier's declared tier, for YOUR policy to weigh
```

CLI: `proofbundle verify-enclave att.eat --receipt receipt.json --verifier-key <b64> [--profile URI]`.

## Corroborating an eval claim's `assurance_level`

`verify-enclave` checks an EAT against a receipt in isolation. A relying party reading an eval
receipt (EVAL_CLAIM.md) usually wants the OTHER direction: *this claim SAYS
`assurance_level = enclave_attested` — is that actually backed by a real attestation, or just a
string the issuer typed?* `proofbundle.evalclaim.enclave_assurance_proven` answers exactly that,
analogous to the Decision Receipt's `action_outcome_proven` (presence + binding makes a declared
property *verifiable*, not merely *asserted*):

```python
from proofbundle.evalclaim import decode_eval_claim, enclave_assurance_proven

claim = decode_eval_claim(receipt_bundle)
proven = enclave_assurance_proven(claim, receipt_bundle, eat_jws=eat_jws,
                                  verifier_pubkey=verifier_key)
# True  — a verified EAT binds THIS receipt
# False — enclave_attested is declared but uncorroborated (no/failing EAT) — the honesty limit
# None  — the claim does not declare enclave_attested at all (not applicable)
```

CLI: `proofbundle show-eval receipt.json --eat att.eat --verifier-key <b64> [--profile URI]` prints
an extra `attested   PROVEN|NOT corroborated` line whenever the claim's `assurance_level` is
`enclave_attested`; a claim with any other level is printed exactly as before (no `attested` line
at all — this is purely additive).

**Never force-promotes.** Calling this does not rewrite the signed claim: an `enclave_attested`
level with no (or a failing) corroboration stays `enclave_attested` in the claim itself — one string
among the four `ASSURANCE_LEVELS`, exactly as issuer-declared and exactly as weak as any other
self-declared level (THREAT_MODEL.md) until a real EAT backs it. The function is a read-only,
additive check, not a claim mutator. Its import of `proofbundle.experimental.enclave` is lazy and
function-local, so merely importing `proofbundle.evalclaim` never fires the `ExperimentalWarning`
above — only actually calling it with an `eat_jws` does.

## What this does NOT establish (must never be claimed)

- That the enclave is genuine — that is the *Verifier's* appraisal, trusted via its key.
- That the TEE vendor's root of trust is sound, or free of known TCB vulnerabilities.
- That the eval inside the enclave was well-designed, uncontaminated, or honest.

It raises the assurance floor from *"the issuer says so"* to *"a Verifier you trust attested the
enclave, bound to this receipt"* — no further. It is standards-native (RFC 9334 + RFC 9711),
offline, and vendor-neutral, in contrast to proprietary certificate + ledger approaches.

## Roadmap for this preview

- Migrate the `tier` field to the IETF **AR4SI / EAR** trustworthiness vector once those drafts
  become RFCs (they are Internet-Drafts as of 2026-07).
- Optional CWT/COSE encoding of the EAT (this preview ships JSON/JWS only).
- Reference Verifier profiles for Intel TDX + NVIDIA GPU, documenting the exact quote user-data
  binding — kept out of the core (they pull vendor tooling).
