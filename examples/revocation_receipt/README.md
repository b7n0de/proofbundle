# Example revocation receipt for an AI agent's authorization

This is a synthetic example of a signed customer revocation statement, with an optional provider-signed acknowledgement. The checker verifies the statement against supplied keys, expected fingerprints and an action time. All data and keys are made up.

## What is in here

- `revocation_customer_only.json` signed by the customer alone.
- `revocation_countersigned.json` the same revocation, plus a countersignature by the agent's provider.
- `keys/` the public keys of the made-up customer and provider.
- `verify_revocation.py` an offline checker, as a bank could run it.
- `cases/` additional test receipts, and `expected.json` with the expected verdict and first non-PASS check for every test run.
- `make_examples.py` rebuilds the public keys, receipts, test cases and `cases/expected.json` from fixed test keys and synthetic inputs. Those keys are worthless on purpose.
- `check_mutants.py` disables each check marked `LOCK`, runs the complete selftest and requires at least one expected result to change. A test-run error is not counted as a caught mutant.

Each receipt file contains a `revocation` DSSE envelope around an in-toto Statement (`_type`,
`subject`, `predicateType`, `predicate`), signed with Ed25519. The countersigned version also contains a separate `countersignature` DSSE envelope around the provider's acknowledgement Statement. The type names under `https://signed-evidence.org/` are
provisional and may change. The receipt names the authorization and the agent only by fingerprint
(SHA-256 over the canonical JSON form), never in clear text.

These unkeyed, unsalted fingerprints bind the signed record to known inputs; they do not conceal guessable contents or prevent equal records from being linked. The example does not define domain-specific identifiers or keys, dispute-only disclosure and salt release, retention periods or deletion markers. Its verdicts check signatures and the listed inputs, not compliance with the seven privacy requirements proposed on the audit list. The supplied receipts contain no cleartext authorization or agent object, but the checker does not enforce that restriction on other receipts.

## What the receipt shows

- Customer only: the holder of the customer key signed a revocation of exactly this authorization
  for exactly this agent, at a time the customer states.
- With countersignature: in addition, the provider signed that it received exactly this revocation
  (bound by its digest), at a time the provider states, which is not before the revocation.

## What it does not show

- That the provider actually stopped the agent. A receipt shows a message, not behaviour.
- Both `revokedAt` and `receivedAt` are signer claims. A trusted timestamp could show that the timestamped receipt existed by a particular time; it would not establish when the revocation became effective or when the provider received it. No third-party timestamp is included.
- That the signing key is authorized to revoke this particular authorization, or that the supplied fingerprints and action time describe the disputed action. The bank must establish these inputs independently of the receipt: the customer key's association with that authorization, the expected authorization and agent fingerprints, and the action time being compared. The provider key must come from a trusted source. The supplied keys and command-line values are fixed inputs for this demonstration.
- That the bank has been notified or has accepted this record as sufficient evidence. In the agreement that prompted this example, Section 15(f) separately requires notice to the bank under Section 17(d). Signing or countersigning this record does not send or prove that notice.

A receipt without countersignature is never a provider confirmation. The checker then says
`VALID_CUSTOMER_ONLY` and "customer-signed only".

## How to run it

You need Python 3 and `pip install cryptography`. Then, in this folder:

```
python3 verify_revocation.py revocation_countersigned.json \
  --customer-key keys/customer.pub.pem --provider-key keys/provider.pub.pem \
  --authority-digest 5ad18961a9784df3fcbb8a8a70ca6875a64df54231376002657abac91792175f \
  --agent-digest b0de8777be13c476276d34c519664d575cfb6d7f9c45c356b978441950ce9707 \
  --action-time 2026-11-25T10:15:00Z
```

Expected: every line `PASS`, last line `VERDICT VALID_PROVIDER_CONFIRMED`, exit code 0. The same
command on `revocation_customer_only.json` ends with `VERDICT VALID_CUSTOMER_ONLY`, exit code 3. A
failed check gives `VERDICT INVALID`, exit code 1. `--action-time` is the caller-supplied time of the action being examined. The checker requires the customer's stated `revokedAt` to be at or before that time. It does not authenticate the action time. `VALID_PROVIDER_CONFIRMED` adds a valid, matching provider-signed acknowledgement whose stated receipt time is not before `revokedAt`; it does not require receipt before the action. The checker keeps no history and does not detect conflicting records that reuse a revocation identifier. Rechecking identical bytes with identical inputs gives the same result.

Times must use ASCII digits in the exact UTC form `YYYY-MM-DDTHH:MM:SSZ`. Fingerprint arguments must be exactly 64 lowercase hexadecimal characters. The checker refuses a supplied public key that is not a canonically encoded Ed25519 point of prime order, such as the identity point, under which a signature made without any private key would verify.

`python3 verify_revocation.py --selftest` runs all 26 test runs and exits 0 only if each result equals
`cases/expected.json`. `python3 check_mutants.py` exits 0 only if every switched-off check turns at
least one case red.

## Where this fits

OAR-00 allows an authority set and defines a re-check immediately before commit (Sections 4.1–4.2). This example could inform an evidence format discussed in Section 11. It does not implement that re-check. Use under Section 4.3 would require binding the receipt to the authority issuer, the authorization artifact and its OAR digest, and the particular re-check time. It is also a candidate for a future revision of our AUDIT decision receipts draft.
