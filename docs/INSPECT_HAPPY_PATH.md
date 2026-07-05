# From an Inspect AI run to a verifiable receipt — the happy path

You run an eval with [Inspect AI](https://inspect.aisi.org.uk/), get a signed receipt next to the
log, attach the receipt to your paper or model card, and any reader verifies it offline in one
command. Nothing here is a claim about *truth* — a receipt proves who signed the reported bytes and
that nothing changed since, and that is exactly what a self-reported eval number lacks today.

Every command below was run against this version; the output is copied from a real run.

## Why this exists

Inspect eval logs are mutable by design — the official API includes an `edit_score(...)` call with
plain-text provenance. That is fine for workflow, but it means a *published* number carries no
tamper evidence. A receipt freezes the claim: these exact bytes, this signing key, unchanged since.

## 0. Install

    pip install "proofbundle[eval]"        # verify/emit/eval-receipt + the demo
    pip install "proofbundle[eval,inspect]" # + the inspect_ai end-of-task hook

The hook needs `inspect_ai >= 0.3.112` (generic lifecycle hooks / `on_task_end`).

## 1. A stable signing key (optional but recommended)

The hook signs with the key at `PROOFBUNDLE_KEY`. If that variable is unset it mints an **ephemeral**
key per run — fine for a quick look, but the public key (your trust anchor) then changes every run.
For anything you publish, keep one key:

    proofbundle emit-eval --claim any_claim.json --out /tmp/throwaway.json --new-key signer.key
    # → "wrote new signing key to signer.key (keep this secret)"

`--new-key` is today the way to mint and save a 32-byte Ed25519 seed; a dedicated `keygen`/`pubkey`
pair is a tracked convenience issue, not yet shipped. Keep `signer.key` mode 0600, out of version
control. Your public key — printed as the `issuer` field of any receipt you sign (step 4) — is what
you publish out of band (repo, ORCID, model card) so a reader can pin it.

## 2. Run the eval with the receipt hook

    export PROOFBUNDLE_EMIT=1              # master opt-in — nothing is emitted without it
    export PROOFBUNDLE_KEY=./signer.key    # omit for an ephemeral key
    # optional: PROOFBUNDLE_OUT=<file-or-dir>, PROOFBUNDLE_METRIC, PROOFBUNDLE_COMPARATOR, PROOFBUNDLE_THRESHOLD
    inspect eval my_task.py --model <model>
    # → your usual eval log, plus proofbundle_receipt_<eval_id>.json

The hook fires on `on_task_end`: it reads the final eval log, builds an eval claim (suite, n, metric,
comparator, threshold), canonicalizes it per RFC 8785, signs it, and anchors the result under a
Merkle root inside the claim. Emission is wrapped so a hook error never fails your eval — it prints
`[proofbundle] ... skipped` and moves on.

## 3. Verify — anyone, offline

    proofbundle verify proofbundle_receipt_<eval_id>.json
    [PASS] ed25519-signature: payload signed by stated key
    [PASS] merkle-inclusion: anchored at index 0 of 1
    => OK

Exit code: `0` OK · `1` a check failed · `2` malformed bundle. No network, no account, no server.

## 4. Read the claim and pin the key

    proofbundle show-eval proofbundle_receipt_<eval_id>.json
    suite      safety-refusal (v1)
    metric     refusal_rate >= 0.80
    passed     True   (n=500)
    assurance  self_attested
    ...
    issuer     ed25519:yDouLPyFaxciug2eSswzHCLbOEMhJO5sg8OKzhlkjQg=
    timestamp  2026-07-05T12:00:00Z
    WARNING    self_attested with no prereg_sha256 — the weakest assurance ...
    => OK

The `issuer` line is the signing key the receipt is bound to. Pin it: a reader compares this string
to the public key you published. `show-eval` is deliberately honest — it prints the assurance level
and warns when a `self_attested` claim carries no pre-registration, so a strong signature never
masks a weak assurance. (For challenge-bound audience/replay binding, `verify --aud <aud> --nonce
<nonce>` enforces RFC 9901 §7.3 when the receipt carries a Key Binding JWT.)

## 5. Tamper demo — do this once, in front of your team

    python - <<'PY'
    import base64, json
    b = json.load(open("proofbundle_receipt_<eval_id>.json"))
    payload = json.loads(base64.b64decode(b["payload_b64"]))
    payload["threshold"] = "0.10"                      # move the goalposts
    b["payload_b64"] = base64.b64encode(json.dumps(payload).encode()).decode()
    json.dump(b, open("tampered.json", "w"))
    PY
    proofbundle verify tampered.json
    [FAIL] ed25519-signature: invalid signature
    => FAILED           # exit 1

Changing one byte of the signed payload breaks the signature. That is the whole point.

## 6. Attach to a paper or model card

Ship `proofbundle_receipt_<eval_id>.json` alongside the result and publish your `issuer` key. See
[examples/](../examples/) for adapter snippets, and [../INTEROP.md](../INTEROP.md) for lm-eval and
promptfoo. What a receipt proves and does not prove is in [../THREAT_MODEL.md](../THREAT_MODEL.md):
authorship and integrity, never that the number is true.
