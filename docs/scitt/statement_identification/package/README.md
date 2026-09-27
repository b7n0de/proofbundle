# Statement identification: a small verifiable package

Three signed statements about one subject, and two references between them, which you can check
offline in about five minutes with Python and two libraries. Nothing here is registered in any
transparency service, and nothing needs one: the point is that a reference to a statement can be
checked without asking a log.

## Check it

You need Python 3.10 or newer and `pip`. From this directory:

```sh
python3 -m venv .venv
. .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install cbor2 cryptography
python3 verify.py
```

`verify.py` prints one line per check and ends with `ALL OK: 0 check(s) failed` and exit status 0,
or with `FAILED` and exit status 1. It reads only the files in this directory, uses only `cbor2`
and `cryptography`, and opens no network connection.

## What is in it

| File | What it is |
|---|---|
| `01-original.cose.hex` | A signed statement: issuer `https://issuer.example`, subject `pkg:generic/example-widget@1.0.0`, JSON payload naming an artifact digest and a license. |
| `02-audit.cose.hex` | An audit statement by another issuer, `https://auditor.example`, about the same subject, with a plain-text payload. It refers to `01`. |
| `03-correction.cose.hex` | A later statement by the first issuer, same subject, different payload (the license corrected). It refers to `01`. |
| `issuer.pub.pem`, `auditor.pub.pem` | The two Ed25519 public keys. The private keys were generated when the package was built and were never written to disk. |
| `references.json` | For every statement its issuer, subject and two digests; for every reference its source, target, digest algorithm, the exact bytes the digest covers and why. |
| `verify.py` | The checker, under 150 lines. |
| `build.py` | How the files were made. Running it again makes new keys and new digests. |

Each statement is a tagged COSE_Sign1 (CBOR tag 18) signed with EdDSA (COSE algorithm -8). The
files hold the exact bytes as hexadecimal text, 64 characters per line; this repository accepts no
binary files. To get the binary form, for example for another COSE tool:

```sh
python3 -c "import pathlib; p=pathlib.Path('01-original.cose.hex'); pathlib.Path('01-original.cose').write_bytes(bytes.fromhex(''.join(p.read_text().split())))"
```

or `xxd -r -p 01-original.cose.hex > 01-original.cose`.

## What the checks show

1. Every statement is a well-formed COSE_Sign1 with tag 18 and algorithm -8, its signature verifies
   under the named public key, and its two digests, its issuer and its subject are the ones
   `references.json` records.
2. Every reference is carried in the protected header of the referring statement, so it is covered
   by that statement's signature, and it is readable without knowing the payload format: `02` has a
   `text/plain` payload, `03` a JSON payload, and the reference is read the same way in both.
3. Every reference names bytes, not an object: its digest is SHA-256 over the ToBeSigned value of
   the referenced statement, and `verify.py` recomputes it.
4. `01` and `03` have the same issuer and the same subject and are different statements; only their
   digests tell them apart. A lookup by subject finds both; the references in `02` and `03` name
   exactly one of them.
5. The same statement in another envelope, untagged and with a parameter added to its unprotected
   header after signing (which is where a transparency service puts a receipt), still verifies and
   has the same ToBeSigned digest, while the digest of the whole COSE_Sign1 bytes changes.

## The bytes a reference covers

ToBeSigned, as defined in RFC 9052 section 4.4: the CBOR array
`["Signature1", protected, external_aad, payload]`, where `protected` is the protected header byte
string exactly as it appears in the COSE_Sign1, `external_aad` is the empty byte string, and
`payload` is the payload byte string. This is the value the issuer's signature is computed over.

Why these bytes and not the whole COSE_Sign1: the unprotected header is not signed, and a
transparency service adds its receipt there, so the whole bytes of the same statement differ
before and after registration, and differ again between two transparency services. The tag and
the encoding of the outer array can also change without touching the signature. ToBeSigned does
not change in any of these cases.

What such a digest does not say: which signature was made over it (a second valid signature over
the same ToBeSigned has the same digest), whether the statement is true, or whether any
transparency service has registered it.

## The reference format used here, and what it is not

A reference is an array `[digest algorithm, covered bytes, digest]`: the COSE algorithm identifier
of the hash (-16 is SHA-256), the text `"ToBeSigned"` (or `"COSE_Sign1"` for the whole bytes), and
the digest as a byte string. The referring statement carries an array of these in its protected
header under label -70001. Integer labels below -65536 are private use in the COSE Header
Parameters registry; this label was chosen for this package only. The package proposes no label, no
format and no vocabulary for what a reference means: the audit and the correction say in their
payloads, in words, why they refer to `01`, and `verify.py` does not read those words.

## Checking with another COSE implementation

`verify.py` builds the ToBeSigned value itself. As an independent check, pycose 1.1.0 (with cbor2
5.9.0 and cryptography 50.0.1) was used on 27 September 2026 to decode each statement with
`Sign1Message.decode`, set the Ed25519 public key and call `verify_signature()`: all three signatures
verify, and the SHA-256 of pycose's own ToBeSigned value equals `sha256_to_be_signed` in
`references.json` for all three. pycose 1.1.0 does not decode any COSE message under cbor2 6.1.4,
which returns CBOR arrays as tuples where pycose expects lists; install `"cbor2<6"` next to it.

## Measured in a fresh virtual environment

On 27 September 2026, 19:23Z, the steps of "Check it" were run on a copy of this directory in a new
virtual environment: CPython 3.11.15, pip 24.0, and from PyPI cbor2 6.1.4 and cryptography 50.0.1
(with cffi 2.1.1 and pycparser 3.0), nothing else installed. `verify.py` printed 22 lines ending in
`ALL OK: 0 check(s) failed` and exited 0; the whole run, from creating the environment to the last
line, took 6 seconds. The same `verify.py` in a Linux network namespace with no network interface up
(`unshare -n`) printed the same 22 lines, byte for byte, and exited 0.

Not measured: other Python versions, other operating systems, and other versions of the two
libraries.

## Rebuilding

`python3 build.py` writes a new package into this directory with two new key pairs. Every signature
and every digest then differs from the committed ones, and `verify.py` checks the new set the same
way.
