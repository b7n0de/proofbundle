# Migration: proofbundle 3.1.0 → 3.1.1

3.1.1 is a patch release. The wire format (bundle / eval-receipt / decision-receipt JSON) is
**unchanged**, existing bundles verify unchanged, and all new fields are additive. There is exactly
**one behaviour change** to be aware of, and it is deliberate and security-motivated.

## 1. `safeForAutomation` is stricter (action may be required)

Before 3.1.1, `verify --json` could report `root_authenticity.safeForAutomation: true` for a
crypto-valid, root-pinned receipt **even when no signer-pinning trust policy had been evaluated**. The
flag is meant to answer "is this safe to act on automatically?", so that was too permissive.

In 3.1.1, `safeForAutomation` is `true` **only** when all of the following hold:

- the cryptographic verification passed;
- the Merkle root was affirmatively authenticated (`--expected-root` or a policy `trusted_roots` /
  `require_authenticated_root`);
- a trust policy was supplied and **passed** (`policy_ok is True` — no policy at all never qualifies);
- that policy actually **pins a trusted signer** (a real `allowed_issuers` /
  `trusted_decision_makers` entry, not the "attributes to nobody" case);
- the policy carries no blocking warning and is **not expired** (`valid_until` in the future);
- no required anchor / public-transparency / replay gate FAILED.

Every reason the flag is false is now listed in the new `automationBlockers` array, and the human
output gains a `SAFE_FOR_AUTOMATION: YES/NO` line with per-blocker reasons.

**What to do:** if you keyed automation off `safeForAutomation`, make sure you pass a trust policy that
pins your expected issuer key(s). The easiest path is to instantiate a shipped template (see below):

```bash
proofbundle policy instantiate strict-eval-template-v1 \
  --issuer-key org-eval.pub --policy-id org/strict-eval-v1 --output org.json
proofbundle verify receipt.json --json --policy org.json --expected-root <b64>
# → "safeForAutomation": true, "automationBlockers": []
```

If you instead relied on the old crypto-only meaning, read `crypto_ok` (exit code 0/1) directly; that
verdict is unchanged.

## 2. Trust-policy profiles renamed to `*-template-v1` (aliases keep working)

The four `strict-*` profiles are renamed to make their template nature explicit:

| Old name (still works, deprecated) | New canonical name |
|---|---|
| `strict-eval-v1` | `strict-eval-template-v1` |
| `strict-eval-authenticated-root-v1` | `strict-eval-authenticated-root-template-v1` |
| `strict-prereg-v1` | `strict-prereg-template-v1` |
| `decision-receipt-v1` | `decision-receipt-template-v1` |

The old names **still resolve** for a deprecation period; using one prints a single deprecation line
on stderr and otherwise behaves identically. Update your scripts to the canonical names at your
convenience; the aliases will be removed in a future **major** release. `research-preview-v1` is
unchanged.

These templates now carry `deploymentReady: false` + `requiresIdentityOverlay: true` and are meant to
be turned into a concrete policy with `proofbundle policy instantiate` before you depend on them for an
automation decision. `policy lint --strict <raw-template>` now fails (a raw template is not
deployment-ready); `policy lint <raw-template>` (non-strict) still passes. See
`docs/POLICY_PROFILES.md`.

## 3. New additive fields (no action required)

- `verify --json` gains `treeSizeExpectation { status, expected, actual }` (AP-3).
- Trust policies may carry an optional `valid_until` (ISO-8601 UTC) expiry.
- `policy list-profiles` output gains template markers and deprecated-alias listings.

## 4. SD-JWT graft refused fail-closed (N1, security)

An **eval** SD-JWT (carrying `passed` / `threshold` / `comparator` / `suite` / `root`) grafted onto a
**non-eval** payload is now refused fail-closed. A **generic** SD-JWT-VC (`iss` / `vct`, no eval
markers) on a non-eval payload is unaffected and stays valid. If you produce eval SD-JWTs, keep them on
eval-claim receipts (the normal `emit-eval` path already does).
