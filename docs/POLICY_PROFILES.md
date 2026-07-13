# Named trust-policy profiles (WP3) and templates (AP-2)

`docs/TRUST_ANCHORS.md` documents the trust-policy *mechanism* (`schema:
proofbundle/trust-policy/v0.1` / `v0.2`, fail-closed parsing, `policy explain` /
`policy lint`). This document lists the concrete, **named** profiles that ship
*inside* the `proofbundle` package (`src/proofbundle/policies/*.json`,
`proofbundle.policy_profiles`) so a relying party can start from a real,
loadable policy instead of hand-writing one.

```bash
proofbundle policy list-profiles                       # what ships; templates are marked, aliases listed
proofbundle policy explain strict-eval-template-v1     # what a green POLICY: OK would mean under it
proofbundle policy lint strict-eval-template-v1        # non-strict: real pins present
proofbundle policy lint --strict strict-eval-template-v1   # FAILs: a raw template is not deployment-ready
```

A profile name may be given **bare** (`strict-eval-template-v1`) or **prefixed**
(`proofbundle-policy/strict-eval-template-v1`, the `policy_id` convention this
audit's WP3 defined) anywhere a policy path is accepted (`policy explain`,
`policy lint`, `policy instantiate`, `verify --policy`). **A real file on disk
always wins**: if a file named `strict-eval-template-v1` (or
`strict-eval-template-v1.json`, as a path) exists in your working directory,
that file is loaded, never the packaged profile of the same name — a profile
name can never silently shadow your own policy file
(`proofbundle.policy_profiles.resolve_policy_source`).

## Template vs instantiated policy (AP-2)

The four `strict-*` profiles are **templates**, not deployment-ready policies.
A template pins the *structural* trust questions (schema version, signature
algorithm, Merkle hash algorithm, issuer-declared assurance level, anchor
shape) but deliberately leaves the **signer identity** unpinned, because
`allowed_issuers[].public_key_b64` (or, for the decision template,
`decision_receipt.trusted_decision_makers[].public_key_b64`) is *your* key —
literally "whose key do you trust" — not something a profile shipped to every
installation can know in advance.

Each template therefore carries two machine-readable flags:

| Field | Meaning |
|---|---|
| `deploymentReady: false` | a raw template, not a deployment-ready policy — `policy lint --strict` fails on it, and `verify` under it can never report `safeForAutomation: true` (blocker `TEMPLATE_NOT_INSTANTIATED`) |
| `requiresIdentityOverlay: true` | this profile must be completed with a signer-identity overlay before use; while it is set, `verify` never marks the signer trusted (eval path: never `safeForAutomation: true`; `decision verify`: a raw decision template cannot authorise a decision → exit 3) |

You turn a template into a deployment-ready policy with **`policy instantiate`**
— fully local, offline, no network:

```bash
# your organisation's trusted eval issuer public key, base64 (the string that appears
# as signature.public_key_b64 in a receipt this issuer signs)
echo "<base64-ed25519-public-key>" > org-eval.pub

proofbundle policy instantiate strict-eval-template-v1 \
  --issuer-key org-eval.pub \
  --policy-id org/strict-eval-v1 \
  --output org-strict-eval-v1.json
```

The result pins your issuer key (`allowed_issuers` +
`signature.require_expected_signer: true`), sets `requiresIdentityOverlay:
false`, takes a new `policy_id` in **your** namespace, and is validated against
the trust-policy schema (unknown overlay fields fail closed). It is
`deploymentReady: true` **only when every required field is filled** — an
authenticated-root template (`strict-eval-authenticated-root-template-v1`) also
needs `--expected-root-file <b64-root>`, else it stays `deploymentReady: false`
(and `policy lint --strict` still refuses it — No-Fake).

Optionally stamp an expiry with `--valid-until 2027-01-01T00:00:00Z`;
`policy lint` fails once it is in the past, and `verify` reports
`safeForAutomation: false` with the `POLICY_EXPIRED` blocker.

Then depend on the *instantiated* policy, which lints clean under `--strict`:

```bash
proofbundle policy lint --strict org-strict-eval-v1.json          # PASS (exit 0)
proofbundle verify receipt.json --policy org-strict-eval-v1.json --expected-root <b64>
```

`research-preview-v1` is the one **non-template** profile: an explicitly
labelled preview a relying party may point `verify` at to sanity-check
structure. It is not a template (it carries no `deploymentReady` /
`requiresIdentityOverlay`) and, like any signerless policy, `verify` under it
prints `POLICY: OK (WARNING: attributes to nobody)` — a passing policy, honestly
annotated, never a claim about *who* signed.

## Deprecated name aliases (AP-2 §6.1)

The four templates were renamed `strict-*` → `*-template-v1` to make their
template nature undeniable. The **old names still resolve** for a deprecation
period as aliases and print a single deprecation line on stderr (no break):

| Deprecated alias | Canonical name |
|---|---|
| `strict-eval-v1` | `strict-eval-template-v1` |
| `strict-eval-authenticated-root-v1` | `strict-eval-authenticated-root-template-v1` |
| `strict-prereg-v1` | `strict-prereg-template-v1` |
| `decision-receipt-v1` | `decision-receipt-template-v1` |

Update to the canonical name; the aliases will be removed in a future major
release. `policy list-profiles` shows the canonical names first and marks each
alias.

## Shipped profiles

| Profile | Kind | Schema | What it pins | What it deliberately leaves to you |
|---|---|---|---|---|
| `research-preview-v1` | profile | v0.1 | bundle `schema` version, `ed25519` signature algorithm, `merkle.hash_alg == sha256-rfc6962` — baseline structural sanity only | assurance level (any level, including `self_attested`, passes), signer identity |
| `strict-eval-template-v1` | template | v0.1 | the above, plus `assurance.minimum_level: reproduced`, `assurance.reject_self_attested_without_prereg: true`, and `sd_jwt.require_key_binding_when_cnf_present: true` | signer identity — instantiate to pin `allowed_issuers` |
| `strict-eval-authenticated-root-template-v1` | template | v0.1 | `strict-eval-template-v1` plus `merkle.require_authenticated_root: true` — the stated Merkle root MUST be authenticated, closing the coherent one-leaf rewrap (ADR 0004). **Fail-closed:** supply the authenticated root out of band (`--expected-root-file` at instantiation, `verify --expected-root <b64>`, or `merkle.trusted_roots`), else the policy FAILs (exit 3) — that is the point | signer identity, and the trusted root itself (deployment-specific) |
| `strict-prereg-template-v1` | template | v0.2 | the structural pins, plus `assurance.reject_self_attested_without_prereg: true` and `anchors.require_anchor_target: preRegistration` (`allow_pending: false`) — the receipt's `anchors[]` must carry a fully verifying (not merely pending) external time anchor stamping the **pre-registration** target, i.e. backdating protection | which anchor **type** (any `rfc3161-tsa` / `opentimestamps` / registered extension satisfies it), the TSA root / Bitcoin header trust material, and signer identity |
| `decision-receipt-template-v1` | template | v0.2 | `decision_receipt.accepted_predicate_types` pinned to the vendored `decision-receipt/v0.1` predicate type (confusion defense), `require_not_checked`, `require_decision_change_conditions`, `require_audience`, `require_nonce` all `true`, `allow_raw_inputs: false` | `trusted_decision_makers` (instantiate to pin), `allowed_decision_types`, `allowed_verdicts`, `required_evidence_relations` — see `docs/predicates/decision-receipt.md` |

`strict-prereg-template-v1` exercises a small companion fix landed alongside
these profiles: `explain_policy` previously never listed the `anchors` section,
so a policy whose *only* pin was `anchors.require_anchor` looked "wirkungslos"
(vacuous) to `policy lint` even though `verify --policy` genuinely gates exit
code 3 on it. `explain_policy` now reports it; the enforcement itself
(`_cmd_verify`) is unchanged.

## Profiles from the audit's WP3 list that are NOT shipped (proposed only)

The v2-audit's WP3 section names two further profiles,
`proofbundle-policy/public-log-required-v1` and
`proofbundle-policy/sdjwt-vc-v1`. Both are **deliberately not shipped**: a
policy JSON that merely *looks* like it pins something the evaluator does not
actually check would itself be a vacuous-pass trap — the exact class
`policy lint` (WP-TP1) exists to catch, and shipping one under this package's
name would be a No-Overclaim violation regardless of how the lint tool scores it.

- **`public-log-required-v1`** — would require a witness-quorum-backed public
  transparency log inclusion (`trusted_log_origins`, `witness_quorum`,
  `require_log_receipt`, `require_consistency_or_checkpoint`). The trust-policy
  schema (`policy.py`) has **no such section today**; the underlying C2SP
  checkpoint/cosignature/tlog-proof verification it would gate already exists
  (SPEC.md §7c/§7d/§7e, `verify-proof`), but there is no policy-file knob for it
  yet. See `docs/PUBLIC_TRANSPARENCY_PROFILE.md`.
- **`sdjwt-vc-v1`** — would require a specific SD-JWT VC `vct` (type) claim. The
  trust-policy `sd_jwt` section has no `vct` field today; the SD-JWT VC profile
  is only partially implemented (RFC 9901 core + the WP-C1/C2 secure-by-default
  checks, not `vct` enforcement or type-metadata resolution). See
  `docs/SD_JWT_VC_PROFILE.md`.

Both remain open, tracked roadmap items (proofbundle#7 adjacent work and issue
#27 respectively) — proposed shapes are sketched in the two documents above, not
implemented here.

## Source of truth

`src/proofbundle/policy_profiles.py` (`PROFILE_NAMES`, `PROFILE_ALIASES`,
`list_profiles`, `profile_path`, `resolve_policy_source`, `instantiate_template`)
and the JSON files under `src/proofbundle/policies/`.
`tests/test_policy_profiles.py` pins that every shipped profile loads, explains
(at least one pin), and lints clean (non-strict), and that
`resolve_policy_source` never lets a profile name shadow a same-named local
file. `tests/test_policy_templates.py` pins the AP-2 template/instantiation
lifecycle (§6.5): a template is not deployment-ready, instantiation pins the
signer (and root when required), an expired instance fails, unknown overlay
fields fail closed, aliases resolve with a warning, and `lint --strict` refuses a
raw template.
