# Statement identification: a small verifiable package

This package contains three synthetic signed statements about one subject and two references between them. Python, cbor2 and cryptography can check the supplied signatures and reference matches offline. Nothing is registered with a Transparency Service. The example illustrates local reference matching; it does not verify Receipts or establish which identification scheme SCITT should adopt.

## Check it

You need Python 3.10 or newer and `pip`. From this directory:

```sh
python3 -m venv .venv
. .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install cbor2 cryptography
python3 verify.py
```

`verify.py` prints one line per check and ends with `ALL OK: 0 check(s) failed` and exit status 0,
or with `FAILED` and exit status 1. Malformed input ends the same way, on a `FAIL` line, the `FAILED`
line and exit status 1. It reads only the files in this directory and uses only `cbor2` and
`cryptography`. The code opens no network connection; installing the two libraries may need one.

## What is in it

| File | What it is |
|---|---|
| `01-original.cose.hex` | A signed statement: issuer `https://issuer.example`, subject `pkg:generic/example-widget@1.0.0`, JSON payload naming an artifact digest and a license. |
| `02-audit.cose.hex` | An audit statement by another issuer, `https://auditor.example`, about the same subject, with a plain-text payload. It refers to `01`. |
| `03-correction.cose.hex` | A later statement by the first issuer, same subject, different payload (the license corrected). It refers to `01`. |
| `issuer.pub.pem`, `auditor.pub.pem` | The two Ed25519 public keys. `build.py` generates the keys in memory and writes the public keys only. |
| `references.json` | For every statement its issuer, subject, size and two digests; for every reference its source, target, digest algorithm, the bytes the digest covers and why. |
| `verify.py` | The checker. |
| `build.py` | How the files were made. Running it again makes new keys and new digests. |

Each statement is a tagged COSE_Sign1 (CBOR tag 18) signed with EdDSA (COSE algorithm -8). The
files hold the exact bytes as hexadecimal text, 64 characters per line; this repository accepts no
binary files. To get the binary form, for example for another COSE tool:

```sh
python3 -c "import pathlib; p=pathlib.Path('01-original.cose.hex'); pathlib.Path('01-original.cose').write_bytes(bytes.fromhex(''.join(p.read_text().split())))"
```

or `xxd -r -p 01-original.cose.hex > 01-original.cose`.

## What the checks show

1. For the supplied statements, the checker verifies tag 18 and algorithm -8, verifies each signature under the named public key, and recomputes the recorded digests. It compares issuer and subject with the manifest. It checks that each statement is a COSE_Sign1 of four elements of the expected types, with no duplicate map key and no trailing input, that the statement files are exactly the ones the manifest lists, and that each recorded `size_bytes` is the file's size. Malformed input ends on the `FAILED` line with exit status 1. It is a package checker, not a general COSE conformance validator.
2. Each reference listed in `references.json` is checked against its signed protected-header entry and against the target's ToBeSigned digest, its `location` against the one form this package uses (the signed protected header, label -70001, an entry index), its `digest_algorithm` against the algorithm in that signed entry, and its `covered_bytes` against the description of the signed covered-bytes element. Every manifest field is either compared with the files or one of three named descriptions (`package`, `reference_format`, `why_these_bytes`), which are not checked; a field the checker does not know fails, and so does a member name that appears twice in one object. The checker also establishes that the manifest lists every reference carried under label -70001 in a signed protected header, and that every listed reference is carried.
3. Reference extraction does not interpret the application payloads: `02` carries text and `03` carries JSON. Their raw payload bytes still participate in signature verification.
4. `01` and `03` share issuer and subject but have different signed contents and ToBeSigned digests. The two references select `01`. All three fixtures share the subject, so subject alone does not select that target.
5. Two transformations of `01`, each on its own. With tag 18 kept, one unprotected parameter is added; separately, tag 18 is removed and nothing else changes. For each, the checker verifies the signature, exact ToBeSigned equality and a changed whole-object digest. The untagged object is a generic COSE case, not an RFC 9943 Signed Statement. The added parameter is an arbitrary private-use parameter, not a Receipt.

These are synthetic fixtures with supplied public keys. No artifact audit, issuer trust configuration, service registration or Receipt is verified. The package illustrates A1–A3 and a limited local invariance property relevant to A4; it does not test A5.

Points 1, 2 and 5 describe the checker as changed after the external review of 27 September 2026.
The review's wording described the checker at `fb1c1786`, which did not establish that the manifest
lists every carried reference, did not check `digest_algorithm`, `size_bytes` or the COSE_Sign1
structure beyond its outer shape, and applied one combined transformation (tag removed and a
parameter added together).

## The bytes a reference covers

This package uses SHA-256 over ToBeSigned, the Sig_structure encoding specified by RFC 9052 sections 4.4 and 9. For its COSE_Sign1 fixtures the structure is ["Signature1", body_protected, external_aad, payload]. The protected value is the original byte-string contents, not a decoded and re-encoded header map. Here external_aad is empty and the payload is embedded.

This choice excludes the signature, unprotected header and outer wrapper. Changes confined to those excluded parts preserve ToBeSigned. It does not normalize the bytes inside the protected header or payload. Other uses must specify external_aad and provide any detached payload; missing inputs cannot establish a match.

A ToBeSigned digest names this chosen class of signed inputs, not a particular signature instance. Matching the digest does not establish signature validity, payload truth, issuer trust or registration.

## The reference format used here, and what it is not

A reference is an array `[digest algorithm, covered bytes, digest]`: the COSE algorithm identifier
of the hash (-16 is SHA-256), the text `"ToBeSigned"` (or `"COSE_Sign1"` for the whole bytes), and
the digest as a byte string. The referring statement carries an array of these in its protected
header under label -70001. Integer labels below -65536 are private use in the COSE Header
Parameters registry; this label was chosen for this package only.

The label and array format are local conventions for this package and are not proposed for standardization. The payloads explain why the audit and correction refer to `01`; reference matching does not interpret that relationship.

## Checking with another COSE implementation

`verify.py` builds the ToBeSigned value itself. As an independent check, pycose 1.1.0 (with cbor2
5.9.0 and cryptography 50.0.1) was used on 27 September 2026 to decode each of the three statements
with `Sign1Message.decode`, set the Ed25519 public key and call `verify_signature()`: all three
signatures verify, and the SHA-256 of pycose's own ToBeSigned value equals `sha256_to_be_signed` in
`references.json` for all three. The statements have not changed since.

To reproduce the independent pycose check, use pycose 1.1.0 with cbor2 5.9.0 and cryptography 50.0.1. No broader compatibility claim is made.

## Measured in a fresh virtual environment

On 8 October 2026, the steps of "Check it" were run on a copy of this directory as committed at
`71abd5b5` (the checker after the Codex threads of 27 September and 8 October on pull request 298, and every
file it reads) in a new virtual environment: CPython 3.10.12, pip 22.0.2, and from PyPI cbor2 6.1.5 and cryptography
50.0.2 (with cffi 2.1.1, pycparser 3.0 and typing_extensions 4.16.0), nothing else installed beyond the
environment's own setuptools. `verify.py` printed 39 lines, 38 checks and the summary
`ALL OK: 0 check(s) failed`, and exited 0. The same `verify.py` in a Linux network namespace with no network
interface up (`unshare -rn`) printed the same 39 lines, byte for byte, and exited 0. The measurement of
27 September 2026 at `7e42877a` (CPython 3.11.15, 29 lines, 28 checks) is the checker before those threads.

Not measured: other Python versions, other operating systems, and other versions of the two
libraries.

## Rebuilding

`python3 build.py` writes a new package into this directory with two new key pairs. Every signature, every
key identifier and every digest in `references.json` then differs from the committed ones, and `verify.py`
checks the new set the same way. What build.py derives from fixed inputs only stays the same: the artifact
digest inside the payloads of `01` and `03` is computed from fixed example bytes, and so are the payloads of
`02`, the issued-at times and the subject.
