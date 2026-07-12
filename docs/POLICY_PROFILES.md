# Named trust-policy profiles (WP3)

`docs/TRUST_ANCHORS.md` documents the trust-policy *mechanism* (`schema:
proofbundle/trust-policy/v0.1` / `v0.2`, fail-closed parsing, `policy explain` /
`policy lint`). This document lists the concrete, **named** profiles that ship
*inside* the `proofbundle` package (`src/proofbundle/policies/*.json`,
`proofbundle.policy_profiles`) so a relying party can start from a real,
loadable policy instead of hand-writing one.

```bash
proofbundle policy list-profiles              # what ships, and how many pins each makes
proofbundle policy explain strict-eval-v1     # what a green `POLICY: OK` would mean under it
proofbundle policy lint strict-eval-v1        # fails on a vacuous/unsatisfiable policy (none are)
proofbundle verify receipt.json --policy strict-eval-v1
```

A profile name may be given **bare** (`strict-eval-v1`) or **prefixed**
(`proofbundle-policy/strict-eval-v1`, the `policy_id` convention this audit's
WP3 defined) anywhere a policy path is accepted (`policy explain`, `policy
lint`, `verify --policy`). **A real file on disk always wins**: if a file
named `strict-eval-v1` (or `strict-eval-v1.json`, as a path) exists in your
working directory, that file is loaded, never the packaged profile of the
same name — a profile name can never silently shadow your own policy file
(`proofbundle.policy_profiles.resolve_policy_source`).

## Honest scope of every shipped profile (No-Overclaim)

**Every profile below is a REAL trust policy** — it loads with
`load_policy`, `policy explain` lists real pins, and `policy lint` passes.
But a profile shipped to *every* installation of the package cannot pin a
signer identity: `allowed_issuers[].public_key_b64` (or, for the decision
profile, `decision_receipt.trusted_decision_makers[].public_key_b64`) is
*your* key, not something a generic template can know in advance. So **none
of these profiles pins a signer** — each one deliberately covers only the
structural trust questions (schema version, signature algorithm, Merkle
hash algorithm, issuer-declared assurance level, anchor shape, decision
structure).

The consequence, and it is deliberate, not a bug: `policy lint <profile>`
reports exactly one warning — `attributes to nobody: the policy pins no
signer` — and `policy lint <profile> --strict` **fails** on every profile as
shipped. That is the honest state of a *template*. Before depending on a
profile for anything beyond "the bytes are structurally sane," add your own
`allowed_issuers` (and `signature.require_expected_signer: true`), or for
the decision profile your own `decision_receipt.trusted_decision_makers`,
the same way `examples/trust_policy_strict.json` shows a *filled-in*, non-
generic worked example with a real pinned demo key. `verify --policy
<profile>` on a signerless profile therefore always prints `POLICY: OK
(WARNING: attributes to nobody)` — a passing policy, honestly annotated,
never a silent claim about *who* signed.

## Shipped profiles

| Profile | Schema | What it pins | What it deliberately leaves to you |
|---|---|---|---|
| `research-preview-v1` | v0.1 | bundle `schema` version, `ed25519` signature algorithm, `merkle.hash_alg == sha256-rfc6962` — baseline structural sanity only | assurance level (any level, including `self_attested`, passes), signer identity |
| `strict-eval-v1` | v0.1 | the above, plus `assurance.minimum_level: reproduced`, `assurance.reject_self_attested_without_prereg: true`, and `sd_jwt.require_key_binding_when_cnf_present: true` | signer identity — mirrors `examples/trust_policy_strict.json` minus its demo `allowed_issuers` pin |
| `strict-prereg-v1` | v0.2 | the structural pins, plus `assurance.reject_self_attested_without_prereg: true` and `anchors.require_anchor_target: preRegistration` (`allow_pending: false`) — the receipt's `anchors[]` must carry a fully verifying (not merely pending) external time anchor stamping the **pre-registration** target, i.e. backdating protection | which anchor **type** (any `rfc3161-tsa` / `opentimestamps` / registered extension satisfies it) and the actual TSA root / Bitcoin header trust material (`--trusted-tsa-root` / `--bitcoin-header`, or your own policy `anchors` trust section — see `docs/ANCHORS.md`) |
| `decision-receipt-v1` | v0.2 | `decision_receipt.accepted_predicate_types` pinned to the vendored `decision-receipt/v0.1` predicate type (confusion defense), `require_not_checked`, `require_decision_change_conditions`, `require_audience`, `require_nonce` all `true`, `allow_raw_inputs: false` | `trusted_decision_makers`, `allowed_decision_types`, `allowed_verdicts`, `required_evidence_relations` — see `docs/predicates/decision-receipt.md` |

`strict-prereg-v1` exercises a small companion fix landed alongside these
profiles: `explain_policy` previously never listed the `anchors` section, so
a policy whose *only* pin was `anchors.require_anchor` looked "wirkungslos"
(vacuous) to `policy lint` even though `verify --policy` genuinely gates
exit code 3 on it (the CLI's `--policy`/`--require-anchor` reconciliation
reads `policy["anchors"]` directly). `explain_policy` now reports it; the
enforcement itself (`_cmd_verify`) is unchanged.

## Profiles from the audit's WP3 list that are NOT shipped (proposed only)

The v2-audit's WP3 section names two further profiles,
`proofbundle-policy/public-log-required-v1` and
`proofbundle-policy/sdjwt-vc-v1`. Both are **deliberately not shipped**: a
policy JSON that merely *looks* like it pins something the evaluator does
not actually check would itself be a vacuous-pass trap — the exact class
`policy lint` (WP-TP1) exists to catch, and shipping one under this
package's name would be a No-Overclaim violation regardless of how the lint
tool scores it.

- **`public-log-required-v1`** — would require a witness-quorum-backed
  public transparency log inclusion (`trusted_log_origins`, `witness_quorum`,
  `require_log_receipt`, `require_consistency_or_checkpoint`). The
  trust-policy schema (`policy.py`) has **no such section today**; the
  underlying C2SP checkpoint/cosignature/tlog-proof verification it would
  gate already exists (SPEC.md §7c/§7d/§7e, `verify-proof`), but there is no
  policy-file knob for it yet. See `docs/PUBLIC_TRANSPARENCY_PROFILE.md`.
- **`sdjwt-vc-v1`** — would require a specific SD-JWT VC `vct` (type) claim.
  The trust-policy `sd_jwt` section has no `vct` field today; the SD-JWT VC
  profile is only partially implemented (RFC 9901 core + the WP-C1/C2
  secure-by-default checks, not `vct` enforcement or type-metadata
  resolution). See `docs/SD_JWT_VC_PROFILE.md`.

Both remain open, tracked roadmap items (proofbundle#7 adjacent work and
issue #27 respectively) — proposed shapes are sketched in the two documents
above, not implemented here.

## Source of truth

`src/proofbundle/policy_profiles.py` (`PROFILE_NAMES`, `list_profiles`,
`profile_path`, `resolve_policy_source`) and the JSON files under
`src/proofbundle/policies/`. `tests/test_policy_profiles.py` pins that every
shipped profile loads, explains (at least one pin), and lints clean
(non-strict), and that `resolve_policy_source` never lets a profile name
shadow a same-named local file.
