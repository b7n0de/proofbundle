# Public Transparency Profile

**Status: split.** The cryptographic mechanics of public log inclusion — a
signed C2SP checkpoint, witness cosignatures, and a full inclusion proof —
are **implemented and normative** (SPEC.md §7c/§7d/§7e). What is **not**
implemented is a trust-*policy* knob that lets a relying party declare "I
require public log inclusion" in a policy file the way `--policy` already
lets them declare "I require this signer" or "I require this assurance
level." That policy-file section is **proposed**, not built, and is
described honestly as such below.

## The one thing this document exists to prevent

A `proofbundle/v0.1` bundle's `merkle.root_b64` (SPEC.md §5) is an **RFC
6962 Merkle root over the bundle's own payload** — a tree the *issuer*
built, containing whatever leaves the issuer chose to include, that no
outside party can see or audit unless the issuer publishes it somewhere.
That local root proves the payload is *one leaf of a tree the issuer
computed*; it proves nothing about whether the tree itself was ever made
public, whether anyone else can see it, or whether the issuer could quietly
maintain more than one version.

A **public transparency log** (C2SP tlog-checkpoint, Certificate-
Transparency-style; Sigstore Rekor v2; SCITT) is a *different* tree, run by
a *log operator* the issuer does not fully control, that anyone can query,
and that is checked for consistency over time so a log cannot quietly
rewrite its own history without getting caught. Confusing the two — reading
"this bundle has a Merkle root" as "this bundle is publicly logged" — is
exactly the No-Overclaim failure this document, and the code it describes,
guards against. **`proofbundle verify` never treats a bundle's own
`merkle.root_b64` as evidence of public inclusion.** Public inclusion is a
*separate*, opt-in artifact (`.tlog-proof`, below) that a relying party
verifies with a *different* command, against *different*, out-of-band
trust anchors (the log's own key, not the bundle issuer's).

## What is implemented today

### 1. A signed checkpoint over a Merkle tree (SPEC.md §7c)

A receipt's Merkle root MAY be published as a
[C2SP tlog-checkpoint](https://github.com/C2SP/C2SP/blob/main/tlog-checkpoint.md):
a signed note naming the log's `origin`, the tree size, and the root, in the
standard C2SP note format (`checkpoint.verify_checkpoint`,
`checkpoint.py`). This is the same wire format Sigstore Rekor v2 and other
C2SP-family transparency logs use — proofbundle does not invent its own
checkpoint format.

### 2. Witness cosignatures — split-view resistance, fully offline (SPEC.md §7d)

A checkpoint MAY carry **witness cosignatures** ([C2SP
tlog-cosignature](https://github.com/C2SP/C2SP/blob/main/tlog-cosignature.md)):
independent third parties (the "witnesses") each sign that they observed
the *same* checkpoint at the *same* tree size. Verifying a `threshold`-of-`n`
quorum of cosignatures, entirely offline, rules out the log operator
quietly showing different histories to different relying parties (a
"split view" attack) — the classic weakness of a single-operator
transparency log. Ed25519 and ML-DSA-44 witnesses (`proofbundle[pq]`)
verify in the same quorum (`checkpoint.verify_witnessed_checkpoint`).

**This is not "trustless."** Split-view resistance requires the witnesses
to be *operationally independent* of the log and of each other — a
deployment property outside what any file format can prove. Two witness
keys controlled by the same operator provide no more resistance than one.

### 3. A self-contained inclusion proof file (SPEC.md §7e)

A `.tlog-proof` file (`c2sp.org/tlog-proof@v1`) bundles an RFC 6962
inclusion proof for one leaf **together with** its signed, witnessed
checkpoint, so a relying party can verify "this exact payload is included,
at this index, under a checkpoint signed by the log and cosigned by a
quorum of witnesses" from **one file, fully offline**:

```bash
proofbundle verify-proof receipt.tlog-proof \
  --payload-file receipt-payload.bin \
  --log-vkey <log's C2SP vkey> \
  --witness-vkey <witness 1 vkey> --witness-vkey <witness 2 vkey> \
  --threshold 2
```

The verdict is the **conjunction** of four independently-reported
sub-checks: the recomputed leaf hash, the log signature, the witness
quorum, and the inclusion-proof binding — never a single opaque pass/fail
(SPEC.md §7e).

## No-Overclaim: what public inclusion proves and does not prove

```text
A verifying `.tlog-proof` proves:
  - this exact payload was included, at this leaf index, in a tree the log
    signed at this size, and (with a witness quorum) that quorum agrees;
  - IF the witnesses are genuinely operationally independent, the log
    cannot show a DIFFERENT history to a different relying party without
    detection.

A verifying `.tlog-proof` does NOT prove:
  - that the payload's CONTENT is true, well-designed, or free of
    cherry-picking (that is the eval receipt's own, separate, honest
    boundary — see docs/NON_CLAIMS.md);
  - that the log operator is trustworthy in any sense beyond "did not get
    caught rewriting history against the witnesses you checked";
  - that this is the ONLY copy the issuer published (an issuer could still
    submit different bundles to different logs, or to none);
  - anything at all, if you did not independently obtain the log's own
    verifier key and a real witness quorum out of band (see
    docs/TRUST_ANCHORS.md's "out-of-band" rule — a log key or witness key
    you did not pin yourself proves nothing to you).
```

## Privacy: what publication reveals

Publishing to a transparency log publishes the checkpoint's **tree root and
size** and, per-entry, the **leaf hash** an inclusion proof binds to — never
the receipt's payload contents. Combined with the same rule stated in
SPEC.md §7i for external time anchors: public anchoring transmits digests
and roots, not the underlying claim, protocol, or sample data.

## The verifier stays offline by default

`proofbundle verify-proof` takes the log/witness keys and the `.tlog-proof`
file as **inputs** — it never fetches a log, a checkpoint, or a key over
the network. Obtaining a *current* checkpoint (to confirm your `.tlog-proof`
is not stale) is necessarily a separate, online step outside this offline
verifier's scope, exactly as obtaining a current TSA root or Bitcoin block
header is for the `anchors[]` layer (docs/ANCHORS.md).

## Proposed, not implemented: a `public-log-required-v1` trust-policy section

The v2-audit sketches a policy section a relying party could pin once,
instead of remembering the right `verify-proof` flags:

```yaml
# PROPOSED shape — not a section the trust-policy loader (policy.py) accepts today.
trusted_log_origins:
  - name: rekor-v2
    origin: rekor.sigstore.dev/...   # the C2SP checkpoint `origin` line to accept
trusted_tsa_roots: []                 # already exists — see the anchors.trusted_tsa_roots section
witness_quorum:
  required: 2
  allowed_witnesses: []               # C2SP witness vkeys
require_log_receipt: true             # a .tlog-proof (or equivalent) MUST accompany the receipt
require_consistency_or_checkpoint: true
```

This is deliberately **not** implemented in `policy.py` today, and the
`proofbundle-policy/public-log-required-v1` named profile
(`docs/POLICY_PROFILES.md`) is deliberately **not shipped**: a policy file
that merely *looks* like it enforces public-log inclusion, when nothing in
`evaluate_policy` actually checks it, would itself be exactly the silent
vacuous-pass trap `policy lint` (WP-TP1) exists to catch — accepting such a
section into the schema without wiring real enforcement would be a
No-Overclaim violation, not a convenience. Building it for real means:

1. threading a verified `.tlog-proof` (or an equivalent structured input)
   into the `verify --policy` code path the way `anchors[]` was threaded in
   (WP4/WP-A1) — today `verify-proof` and `verify` are separate commands
   with separate inputs;
2. extending `policy.py`'s schema + `evaluate_policy` with the section
   above, fail-closed, with its own positive/negative tests, mirroring how
   `anchors.require_anchor` was added; and
3. deciding whether "confirmed public inclusion" ever becomes a
   *precondition* for a `strict-*` profile the way `strict-prereg-template-v1`
   already requires a confirmed pre-registration anchor.

None of that is built in this change; this document is the honest
specification of the gap, not a claim that it is closed.
