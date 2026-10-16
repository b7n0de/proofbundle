# Signers: a key file or a token

Every command that signs (`emit`, `emit-eval`, `intoto`, `svr`, `decision emit`, `outcome emit`,
`relation-statement emit`) takes its Ed25519 key from one of two places. The receipt is the same either way.

| | Key file (default) | PKCS#11 token (optional) |
|---|---|---|
| Option | `--key FILE` or `--new-key FILE` | `--key-uri 'pkcs11:…'` and, optionally, `--pin-env NAME` |
| Install | `proofbundle` | `proofbundle[pkcs11]` |
| Where the key is | a 32-byte raw seed file, mode 0600 | inside the token; the process never reads it |
| What a signature needs | read access to the file | the token present and its PIN |
| Suits | pipelines that sign without a person present: CI, the pytest and Inspect plugins | signatures a person gives on purpose: an audit, an official release, a record of a sensitive decision |

The key file stays the default because a hardware key makes a fully unattended pipeline harder: someone has
to plug the token in and give the PIN. Use a token where that is the point.

## What a verifier sees

A receipt carries the public key and the signature, nothing about where the key was kept. Ed25519 is
deterministic, so the same key signs the same bytes to the same signature: a token holding a key and a file
holding the same key make byte-identical receipts (measured in `tests/test_signer_pkcs11_softhsm.py` with a
key imported into a SoftHSM2 token). The verifier therefore needs nothing new, and it cannot tell a token
signature from a file signature. That a key lives in hardware is the signer's own statement, never a property
a verifier checks; see [NON_CLAIMS.md](NON_CLAIMS.md).

## Signing with a token

```bash
python -m pip install 'proofbundle[pkcs11]'
proofbundle emit-eval --claim claim.json --out receipt.json \
  --key-uri 'pkcs11:token=release;object=release-key?module-path=/usr/lib/softhsm/libsofthsm2.so'
proofbundle show-eval receipt.json --expect-issuer 'ed25519:<the key id of the token key>'
```

Without `--pin-env` the command asks for the PIN on the terminal. For a script, put the PIN into an
environment variable and give its name: `--pin-env PB_TOKEN_PIN`.

In Python:

```python
from proofbundle.evalclaim import emit_eval_receipt
from proofbundle.signer import Pkcs11Signer, pin_from_prompt

uri = "pkcs11:token=release;object=release-key?module-path=/usr/lib/softhsm/libsofthsm2.so"
with Pkcs11Signer.open(uri, pin=pin_from_prompt()) as signer:
    record = signer.sign_bytes(b"bytes to sign")   # record.signature, record.algorithm, record.key_id
    receipt = emit_eval_receipt(claim, signer)
```

Every producer of the package accepts such a signer where it accepts a key, because it asks only for
`sign(data)` and `public_key()`. `sign_bytes` is the same act with its whole answer: the signature, the
algorithm (`ed25519`) and the key id (`ed25519:` and the base64 of the public key, the form a receipt names its
issuer in).

## The URI

The key is selected by a PKCS#11 URI (RFC 7512). The reader is strict:

- The module is named by its absolute path, `?module-path=/path/to/module.so`. `module-name` is refused, and
  so is a relative path. Loading a module runs its code in the process, so name only a module you trust.
- The path may name `token`, `manufacturer`, `model`, `serial`, `slot-id`, `slot-description`,
  `slot-manufacturer`, `library-manufacturer`, `library-description`, `library-version`, `object`, `id` and
  `type` (only `private`, or none). An attribute not named matches everything; an attribute named twice, a
  malformed percent-encoding, a value that is not UTF-8 or does not fit its PKCS#11 field, and any attribute
  the reader does not know are refused.
- Exactly one initialised token and exactly one private key must match. Two matches are an error, not a
  choice. A slot the module cannot read is an error too, so a second token of the same name cannot hide
  behind it.
- RFC 7512 says an unknown query attribute should be ignored. This reader refuses it, so that no part of a
  URI that selects a signing key is silently dropped.
- No refusal repeats a value of the URI, so a PIN pasted into the wrong place does not reach a terminal or a
  log.

## The PIN

The PIN never stands in the URI (`pin-value` and `pin-source` are refused), on the command line, in a file
or in a log. It comes from a prompt on the terminal without echo, or from the environment variable that
`--pin-env` names. Without a terminal and without `--pin-env` the command does not read standard input; it
stops and names `--pin-env`. `--pin-env` takes a variable name; if the value given is no valid name, or the
variable is unset, the refusal does not show it, in case a PIN was typed there. The signer does not keep the
PIN after the login.

## When the token fails

A wrong PIN, a token that is absent or removed, a missing key, a key that is no Ed25519 signing key (an RSA,
a P-256 or an Ed448 key), a token without the CKM_EDDSA mechanism, a private key without its public key
object: each ends the command with exit 2 and a message that names the reason. Nothing is signed, nothing is
written, and no key file is read, written or generated afterwards. There is no fallback to a key file.

Each signature the token returns is checked against the token's public key before it is used. A token that
answers with a signature of another key, or a corrupted one, makes no receipt.

## One algorithm

The verifier checks receipt signatures as Ed25519, so a signer signs Ed25519 and nothing else. A token or a
key that offers only other algorithms is refused before anything is signed. No signer converts or wraps
another algorithm.

## A key management service

`proofbundle.signer.ExternalSigner` is the interface for a key the process cannot read: a token, an HSM, a
cloud KMS. A subclass passes the raw Ed25519 public key to the constructor and implements
`_sign_external(data) -> bytes`; the base checks every signature it returns, refuses a public key that nobody
can hold a secret for (a low-order or non-canonical key) and refuses any algorithm but `ed25519`. The package
ships no KMS provider. An adapter for one is this subclass and nothing more.

## First use case: signing a release

The release artifacts of this project carry a 64-byte Ed25519 signature over a payload file. Today the
maintainer's signing script mounts an encrypted disk image that holds the release key as a file, checks that
the key's public part is the published release anchor, runs a check before, signs the payload with
`openssl pkeyutl -sign -rawin`, unmounts the image and runs a check after.

With a token the key would be generated in, or imported once into, a token that stays with the maintainer.
Mounting the image and reading the key file become inserting the token and entering the PIN. The anchor check
compares `signer.public_key_raw()` (or `signer.key_id`) with the anchor. The signature is
`Pkcs11Signer.sign_bytes(payload).signature`, which for the same key is byte-identical to what OpenSSL writes,
so the checks before and after and every verifier stay as they are.

This is a description, not a change: the release signing path is not switched. Moving the release key into a
token is a decision about its custody and is taken separately.

## What was measured, and what was not

Measured: SoftHSM2 2.6.1 through python-pkcs11 0.10.0, on Linux x86_64 with CPython 3.10.12, by
`tests/test_signer_pkcs11_softhsm.py` (a token the test run creates, a random test PIN, keys the run
generates). Not measured: any hardware token, smartcard or network HSM; any other PKCS#11 module; macOS and
Windows; a token with a PIN pad (a protected authentication path), which this signer does not support. The
SoftHSM tests are skipped where SoftHSM2 or python-pkcs11 is missing, which is the case in this project's CI.
