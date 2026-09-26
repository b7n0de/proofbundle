# SCITT CCF receipts from a real service, recomputed offline

This directory fetches real transparent statements with CCF receipts at pinned commits and
recomputes, offline, the data-hash, the leaf, the Merkle root and the receipt signature.
Verdict: on four registered statements, one of them from the production Microsoft Signing
Transparency ledger, the data-hash is SHA-256 over the statement with tag 18 kept, the
unprotected header replaced by an empty map, and protected header, payload and signature as
served; every receipt signature verifies over the recomputed root with the published trust
material, and every comparison fails when one input bit is changed.

It is a measuring aid for ADR 0009 (`docs/adr/0009-scitt-anchor-cose-profile.md`), not a basis
for `src/`. Nothing here touches the library.

## THE FOUR VALUES

Named apart in every file of this directory and in `recompute_result.json`.

1. Hash envelope payload. The digest of an artifact, carried as the payload of an RFC 9995 COSE
   Hash Envelope (label 258 hash algorithm, 259 preimage content type, 260 location; label 3
   forbidden). In a proofbundle anchor it is the digest of the anchored target.
2. Local ToBeSigned ID. A local rule, versioned. Measured here as SHA-256 over the RFC 9052
   Sig_structure only to show that it is a different value from 3.
3. CCF data-hash. The third component of the CCF leaf; SHA-256 over the registered signed
   statement bytes, by the service's rule. Which bytes those are is what this tool measures.
4. CCF Merkle root. Computed from the inclusion proof; the detached payload over which the
   receipt signature is checked.

Value 2 never replaces value 3. The probe "one ToBeSigned signed twice" below shows why: equal
value 2, different value 3.

## SOURCES

All retrieved on 2026-09-25. Sizes and digests are of the bytes as fetched.

Real statements, receipts and trust material, MIT licence (`LICENSE`, Copyright (c) Microsoft
Corporation), bytes introduced by commit `b325fffa54238f60b1024bdcf2d974bb4bbec662` (2026-09-18,
"Regenerate the conformance corpus on a long-lived service"):
https://github.com/microsoft/scitt-verifier/tree/bd6fb8ba79dbb521257b7f09682c03c6681dc3d0/corpus/fixtures

| file | size | sha256 | role here |
|---|---|---|---|
| `transparent-statement.cose` | 5401 B | `4bb50fe1a92f74cd85405a15508f560f1bfd77a43e1d00d4b3d718cf5d112377` | PS256 statement, one receipt; the control |
| `cbor-header.cose` | 3411 B | `78c91991c8a92aa169da7a6e2ad43e5d5c7bd5165d0f306c3fca6af92a5bcb46` | ES256 statement, one receipt |
| `nested-sign1.cose` | 3353 B | `9f04814fd5d21c4e921c72369d3b68ed01cdeef4dfed00965160dd56c88c42c1` | ES256 statement, one receipt |
| `appended-receipt.cose` | 5989 B | `871109cfb997a19187df71106c7507abb39171194bf88a722dbdee0f0bdeb56c` | control plus a second, corrupted receipt |
| `payload-tampered.cose` | 5401 B | `0b16482599ab0209bbb2b7cb605e71ab8df823cd865c1c172727ecad239503d1` | crossed statement and receipt |
| `tampered-statement.cose` | 5401 B | `075797b10f73d15f699f907c2ac7150ab87b4afe8d979238d650d497982cec2a` | one byte of the receipt changed |
| `hash-envelope.cose` | 702 B | `4a16941a117dff754fe5118e72f28bcabf9bda1312f959a0394b92e2073002f7` | RFC 9995 hash envelope, no receipt; value 1 |
| `hash-envelope-artifact.spdx.json` | 57 B | `a3c890a2ef462e1629270e489f7d41ac02c285a556bd411fb58f5aebf9e51ce0` | the artifact of value 1 |
| `hash-envelope-bad-artifact.spdx.json` | 44 B | `d6e26054fcf7385d419489e4029b751269568d96364cb697f73212fcab550300` | a different artifact |
| `mst-test-scitt-keys.cbor` | 175 B | `b146b954b2ba79eec5e59748d96064b5f18dfe4b13f90cf5868207985d6faf0e` | the service's COSE_KeySet, the trust material |
| `other-service-scitt-keys.cbor` | 523 B | `f113c423176de67543c5f8d55e18c5779506e3ab16d1f3122a4365f7d0301d40` | key set of another service |

A transparent statement from the production Microsoft Signing Transparency ledger (issuer
`esrp-cts-db.confidential-ledger.azure.com`) whose signed statement is an RFC 9995 hash envelope,
the service trust store the repository's own test `test_validate_structured_output` checks it
against, and a statement carrying a receipt in the legacy pre-RFC 9942 form. MIT licence
(`LICENSE.txt`, Copyright (c) Microsoft Corporation):
https://github.com/microsoft/scitt-ccf-ledger/tree/00101f769d872711356e080fbb089ac48589c60a/test

| file | size | sha256 | role here |
|---|---|---|---|
| `uvm_0.2.10.cose` | 6145 B | `f4f5321316ac3cf876292f41cb7bdcd1056aef3a815fb137887a4ef93c3210bc` | production statement: PS384 hash envelope (258 = SHA-384), one ES384 receipt |
| `esrp-cts-db.json` | 6505 B | `295b5824129179cb6a0699b2759ce408c0fe13b364e7a59ad226a68f7265a490` | its trust material: eight CCF service certificates |
| `cts-hashv-cwtclaims-b64url.cose` | 5624 B | `213105fdc0da9022c20e8f49195d0bb621cedf87fdee29aad80e2e605af94c87` | PS256 statement whose receipt is in the legacy two-element form |

A receipt from the production Microsoft Signing Transparency ledger, without its statement,
from the working group's repository of the CCF profile at the commit tagged
`draft-ietf-scitt-receipts-ccf-profile-05`, added there by commit
`54f887f0eef26bdac4e667d63b10d328b54a5442` (2026-06-24). Terms: contributions to the IETF under
BCP 78/79 and the IETF Trust Legal Provisions (`CONTRIBUTING.md` of that repository):
https://github.com/ietf-wg-scitt/draft-ietf-scitt-receipts-ccf-profile/blob/e729c2ec037ac763d0cf422bb58a219f8d6a02f4/samples/microsoft-mst-receipt.cbor

| file | size | sha256 |
|---|---|---|
| `microsoft-mst-receipt.cbor` | 725 B | `db2398e1c9d140619e484d277a05eb186d7d78f91c01f49e595f6047b98249f5` |

What is committed, and what stays fetched (owner answer N3 b, 2026-09-25). The two Microsoft
repositories allow redistribution under MIT with their notice (`LICENSE` of scitt-verifier, 1074 B,
sha256 `7df20dcdf9197e9945c14858d41c60f11b52b93e5b69e2b63416b874d598d322`; `LICENSE.txt` of
scitt-ccf-ledger, 1073 B, sha256 `fd532481d828e13a0b13ccb598e02338a3617740675a862ee6bdc1541b68e93d`;
both read at the pinned commits, both "Copyright (c) Microsoft Corporation."). Their statements and
key sets used by the tests are committed as JSON, not as binary files (`AGENTS.md`):
`fetch_external.py --write-fixtures` writes `tests/fixtures/scitt_ccf/third_party_scitt_verifier.json`
(7 files, 40091 B) and `third_party_scitt_ccf_ledger.json` (3 files, 27683 B) from bytes held
against the pins. Every entry is labelled `"origin": "third-party bytes"` with its source address
at the pinned commit and its licence, and each file carries the licence text verbatim.
`tests/fixtures/scitt_ccf/PROVENANCE.json` names the origin of every file in that directory. The
working group repository's terms are the IETF's, not a plain redistribution grant, so its sample
stays fetch-only, as do the scitt-verifier files the tests do not read. `fetch_external.py` pins
every file by size and sha256 and stops on a mismatch.

Text read at source for the rules, not fetched by the tool:

| what | where | size, sha256 |
|---|---|---|
| CCF profile -05, source text at the tag (commit date 2026-09-23) | https://github.com/ietf-wg-scitt/draft-ietf-scitt-receipts-ccf-profile/blob/e729c2ec037ac763d0cf422bb58a219f8d6a02f4/draft-ietf-scitt-receipts-ccf-profile.md | 22426 B, `7efdb7aa934ab0cfc1093e99932f7d2efd39bb66f5bf43594806d7b282ca0077` |
| service registration code, scitt-ccf-ledger (MIT) | https://github.com/microsoft/scitt-ccf-ledger/blob/00101f769d872711356e080fbb089ac48589c60a/app/src/main.cpp | not pinned |
| CCF version named by that repository | https://github.com/microsoft/scitt-ccf-ledger/blob/00101f769d872711356e080fbb089ac48589c60a/docker/Dockerfile | `CCF_VERSION="7.0.17"` |
| the edit that empties the unprotected header, CCF 7.0.17 (Apache-2.0) | https://github.com/microsoft/CCF/blob/ccf-7.0.17/src/crypto/cose.cpp | 5027 B, `97982db318771ac293d0162fd2003520ee0964752355bcf041502c5b6c18358e` |
| SCITT architecture, WG source at its last commit (2025-10-17) | https://github.com/ietf-wg-scitt/draft-ietf-scitt-architecture/blob/ba7d23d40557f0206735592036532414139d9a57/draft-ietf-scitt-architecture.md | `67c439c0b738546c0ab43f5ba062840356cb6d97d6780eb32d36b15a5e2ca0dd` |
| COSE Hash Envelope, WG source (2025-10-28) | https://github.com/cose-wg/draft-ietf-cose-hash-envelope/tree/5a07f912582f45dc533f12d9113d710fd78c2342 | not pinned |
| COSE Receipts, WG source (2026-06-15) | https://github.com/cose-wg/draft-ietf-cose-merkle-tree-proofs/tree/df5113e94e6b6788de0bfb112db63726516b88ab | not pinned |

The published RFC texts (RFC 9942, RFC 9943, RFC 9995, RFC 9052) and the IETF archive copy of
-05 were NOT MEASURED: `www.ietf.org`, `datatracker.ietf.org` and `www.rfc-editor.org` are blocked
by this environment's egress policy. The working group sources above are the closest text that
was reachable; a difference between them and the published RFC is not excluded.

## WHAT WAS MEASURED

Environment: CPython 3.11.15, x86_64, `cryptography` 50.0.1, 2026-09-25. Recorded in full in
`recompute_result.json`.

| statement | alg | receipt txid | receipt iat (signed) | data-hash (value 3) | Merkle root (value 4) | readable | signature valid | bound to statement | receipt profile satisfied |
|---|---|---|---|---|---|---|---|---|---|
| transparent-statement | PS256 | 2.58 | 2026-09-18T19:47:30Z | `6f7607e4…0e6d11` | `c8dee06d…788c14` | yes | yes | yes | yes |
| cbor-header | ES256 | 2.60 | 2026-09-18T19:47:34Z | `8e465c29…3e1392` | `aa715eb9…3fd76a` | yes | yes | yes | yes |
| nested-sign1 | ES256 | 2.62 | 2026-09-18T19:47:39Z | `40bd53ef…2795f0` | `e36ab9b0…6b92bd` | yes | yes | yes | yes |
| appended-receipt, receipt 0 | PS256 | 2.58 | same as control | `6f7607e4…0e6d11` | `c8dee06d…788c14` | yes | yes | yes | yes |
| appended-receipt, receipt 1 | PS256 | 2.58 | same as control | `6f7607e4…0e6d11` | `c8dee06d…788c14` | yes | **no** | yes | no |
| payload-tampered | PS256 | 2.58 | same as control | receipt `6f7607e4…`, statement `aab9c122…` | `c8dee06d…788c14` | yes | yes | **no** | no |
| tampered-statement | PS256 | 2.58 | same as control | `6f7607e4…0e6d11` | `c8dee06d…788c14` | yes | **no** | yes | no |
| **uvm_0.2.10, production** | PS384 | 458.12441 | 2025-12-22T21:11:28Z | `a60138fb…612649` | `9a9b4394…3b0466` | yes | yes | yes | yes |
| cts-hashv-cwtclaims (legacy receipt) | PS256 | n/a | n/a | not in the legacy leaf | n/a | **no** | NOT EVALUATED | NOT EVALUATED | no |
| microsoft-mst-receipt (receipt only) | n/a | 138.3388 | 2025-06-19T22:05:41Z | `ad2c00a9…bfcd` (statement not published) | `9bfd2a85…ac083` | yes | NOT EVALUATED | NOT MEASURABLE | no |

Readable, signature valid and profile satisfied are three separate results, as ADR 0009 requires.
The last column is the **receipt side** of the profile (`receipt_profile_satisfied` in the JSON):
readable, vds 2, payload detached, every inclusion proof computes the same root, the ES384
signature verifies over that root with a key selected from the trust material, and the leaf's
data-hash equals value 3 recomputed from the statement. The statement side (value 1 as a hash
envelope equal to a proofbundle root) is reported per statement and is not folded in: no real
statement here is a proofbundle anchor, so none can satisfy ADR 0009's v1 end to end.

The legacy receipt of `cts-hashv-cwtclaims-b64url.cose` is a two-element array (a protected map
with text keys such as `tree_alg: "CCF"`, then signature, node certificate, path and a leaf of two
components without a data-hash). It is not a COSE_Sign1 and not the -05 form, so it is not
readable under this profile, by design.

The -05 receipts carry: alg -35 (ES384), kid (label 4) as 64 ASCII hex characters, vds (395) 2,
CWT claims (15) with iss (`mst-test-scitt-verifier.confidential-ledger.azure.com`, or
`esrp-cts-db.confidential-ledger.azure.com` for the production one) and sub
`scitt.ccf.signature.v1`, a `ccf.v1` map with `txid`, no crit (label 2), payload nil, and the
inclusion proof under 396 / -1. The leaf input is 96 bytes in every case.

The production statement carries CBOR **tag 1** (epoch date) around its CWT `iat` (label 6 inside
label 15 of the protected header). No other statement or receipt measured carries a tag besides
the outer 18. cbor2 5.9.0 and 6.1.4 both decode that value to a `datetime`.

Held against the upstream project's own pinned values for `transparent-statement.cose`
(`corpus/README.md` at the pinned commit, computed there with other code): signed statement
length 4809, claim digest `6f7607e4d68fd01298c47897357a093944de8c033c99bbb3284b8243aa0e6d11`,
Merkle root `c8dee06dcaa9268cd2910ca78d24a18490789a9d24acba96534dfe8f3b788c14`. All three equal.

Value 1, measured on `hash-envelope.cose` (a real RFC 9995 statement, not registered): label 258
is -16 (SHA-256) in the protected header and absent from the unprotected one, 259 is
`application/spdx+json`, 260 and label 3 are absent in both buckets, the 32-byte payload equals
SHA-256 of `hash-envelope-artifact.spdx.json` and differs from SHA-256 of the bad artifact.
On the registered production statement `uvm_0.2.10.cose`: 258 is -43 (SHA-384) in the protected
header only, 259 is `application/octet-stream`, 260 and label 3 absent, the payload is 48 bytes;
the hashed artifact is not published, so its match is NOT MEASURABLE.

Value 2, per statement, SHA-256 over the Sig_structure with an empty external_aad, for example
`0efd79b69cd4f4d4e99be43be33ae5e4ea9626426f77488567f0fee66d3106c4` (4432 B ToBeSigned) for the
control. It equals none of the data-hashes.

## THE MEASURED DATA-HASH INPUT RULE

Eight candidate byte strings per statement, each hashed and held against the data-hash in the
receipt's leaf. Measured on the four registered statements with a -05 receipt (three from the
test service, `uvm_0.2.10.cose` from the production ledger) and on the three mutants that share
the control's receipt. Lengths for the control:

| candidate | control length | equals the receipt's data-hash |
|---|---|---|
| file as served (receipt still inside) | 5401 B | no |
| **tag 18, unprotected header replaced by `a0`, other elements as served** | **4809 B** | **yes, in all four statements** |
| same, untagged | 4808 B | no |
| same, tagged, payload replaced by nil (`f6`) | 4788 B | no |
| tag 18, re-encoded from the decoded values in shortest form | 4809 B | yes, in all four statements |
| ToBeSigned (Sig_structure) | 4432 B | no |
| payload alone | 21 B | no |
| protected header alone | 4394 B | no |

So the bytes that enter the data-hash are, measured:

    d2 84 <protected bstr as served> a0 <payload bstr as served> <signature bstr as served>

- unprotected header: cleared to an empty map, not merely stripped of label 394
- tag: included, `d2` (tag 18)
- payload: embedded, as served
- outer array: definite, `84`

This matches the service's code read at source: `app/src/main.cpp` in scitt-ccf-ledger calls
`ccf::cose::edit::set_unprotected_header(body, desc::Empty{})` and binds
`ClaimsDigest::Digest(signed_statement)`; in CCF 7.0.17 that function parses the input, requires
tag 18 ("Failed to parse COSE_Sign1 tag"), and serialises a new tag 18 array of protected header,
an empty map, payload and signature. It matches the architecture text too: "the unprotected
header of a Signed Statement MUST be set to an empty map before the Signed Statement can be
included in a Statement Sequence" (WG source, section "Registration of Signed Statements").

Where the measurement stops:

- Every measured statement uses shortest-form heads and definite lengths, so the spliced rule and
  the re-encoded rule give the same bytes (the production statement's tag 1 is inside the
  protected bstr and therefore copied, not re-encoded, under both rules). Which of the two a service applies to a non-shortest
  or indefinite-length submission is NOT MEASURABLE without registering such a statement; the CCF
  source suggests re-serialisation, the serializer's treatment of head widths was not traced.
- Every measured statement is tagged. An untagged submission is refused by the CCF 7.0.17 code
  (source reading); NOT MEASURED on a service.
- Every measured statement has an embedded payload. The data-hash of a statement registered with
  a detached payload is NOT MEASURED; the code copies the payload element as it is, so nil would
  stay nil.
- Every measured statement carries only label 394 in its unprotected header, so "emptied" and
  "receipts removed" cannot be told apart by these bytes. The code empties the whole map.
- Which CCF version either service runs is NOT MEASURED; the receipts do not carry it.

## THE LEAF, AGAINST THE TWO READINGS OF -04

`tools/scitt_ccf_merkle_lesarten/` measured that two literal readings of -04 compute different
roots and left open what a real CCF instance computes. Held against the real receipt of the
control, with the rest unchanged:

| leaf | receipt signature |
|---|---|
| `HASH(CBOR([itx, evidence, data-hash]))`, the -04 reading of section 2.1 | does not verify |
| `HASH(itx ‖ evidence ‖ data-hash)`, evidence not hashed | does not verify |
| `HASH(itx ‖ HASH(evidence) ‖ data-hash)`, -04 section 3.2 and -05 | verifies |

-05 states the third form explicitly (section "Transaction Components").

## TRUST MATERIAL

- For the test service: the COSE_KeySet published next to the statements at the pinned commit.
  For the production ledger: the JSON trust store of eight CCF service certificates next to the
  statement in scitt-ccf-ledger, two distinct P-384 keys, each re-certified several times. The key
  is selected by kid; the kid is not trust.
- `hex(SHA-256(SubjectPublicKeyInfo))` of the key equals its kid on every -05 receipt measured,
  test service and production alike. This is the self-binding the upstream tool
  `tools/scitt-keys.py` asserts when it fetches a set (`docs/trust-material.md` in
  microsoft/scitt-verifier at the pinned commit). In the trust store, `serviceId` equals SHA-256
  of each certificate, measured for all eight.
- The trust store labels every entry `"signatureAlgorithm": "ES256"`, while every key is P-384 and
  the receipt it verifies says ES384 (-35) in its protected header. The label disagrees with the
  key; verification works only because the algorithm is taken from the receipt, never from the
  store. This is a real instance of why ADR 0009 binds the algorithm to the signed object.
- NOT MEASURED: that this key set is what the live service serves today. The upstream document
  records a fetch of 175 B with sha256 `b146b954…`, equal to the pinned file, but the service
  (`mst-test-scitt-verifier.confidential-ledger.azure.com`) and the Azure identity service
  (`identity.confidential-ledger.core.azure.com`) are blocked here, so no independent fetch was
  made. Authenticity rests on the GitHub commit. The same holds for the production trust store:
  NOT MEASURED against `esrp-cts-db.confidential-ledger.azure.com`.
- NOT MEASURABLE here: the signature of the production receipt `microsoft-mst-receipt.cbor`
  (issuer `esrp-cts-cp.confidential-ledger.azure.com`, kid `a7ad3b77…a10f`). No trust material
  for it is in reach: the service host is blocked, and no pinned copy of its key was found in the
  sources above. Its leaf and root are recomputed; its binding to a statement is not measurable
  because the statement is not published with the sample.
- The statements' own signatures are checked with the leaf certificate of their `x5chain`. That
  is a consistency check and is labelled so in the output: a key taken from the evidence is not
  trust, and nothing here judges the signer.

## PROBES

Each comparison is shown to fail once, next to an unchanged control. From
`probes_on_transparent_statement` in `recompute_result.json`:

| probe | outcome |
|---|---|
| control, unchanged | signature valid, bound, receipt profile satisfied |
| one bit of the statement's signature flipped | data-hash rule no longer matches; statement signature invalid; receipt signature still valid over its own root; profile not satisfied |
| one bit of the first path hash flipped | receipt signature invalid |
| external_aad `00` instead of empty | receipt signature invalid |
| synthetic: one ToBeSigned signed twice with ECDSA P-256, key generated here | value 2 equal, value 3 different, both signatures valid |
| key set of another service | signature not evaluated (kid absent), profile not satisfied |
| no key set | signature not evaluated, profile not satisfied |

The last two are deliberately a different outcome from "invalid": missing trust is not a forged
receipt, and it never satisfies the profile.

## READERS: cbor2 AND pycose

`reader_crosscheck.py` runs the same statements through cbor2, and through pycose where it can,
once per environment. Two environments on 2026-09-25, CPython 3.11.15, `cryptography` 50.0.1,
`pycose` 1.1.0, results in `reader_crosscheck.json`:

| fact | cbor2 5.9.0 | cbor2 6.1.4 |
|---|---|---|
| duplicate map key, default | accepted, last value wins | accepted, last value wins |
| `allow_duplicate_keys=False` | option absent (TypeError) | rejected |
| `allow_indefinite=False` | option absent | rejected |
| `max_depth` | present, default 400 | present, default 400 |
| trailing byte after the item (`loads`) | ignored silently | ignored silently |
| position after the first item (`CBORDecoder.decode`, then `tell()`) | 1 of 2 | 1 of 2 |
| non-shortest head `18 01` | accepted as 1 | accepted as 1 |
| content of tag 18 | `list` | `tuple` |
| map inside tag 18 | `dict` | `frozendict` |
| tags 1, 2, 28/29, 256/25, 55799 by default | interpreted (datetime, int, shared and string references resolved, 55799 dropped) | same |
| `tag_hook` called for tag 2 | no | no |
| `semantic_decoders` to refuse tag 2 | option absent | refuses |
| data-hash recomputed from cbor2's values equals the receipt's | yes, 4 of 4 | yes, 4 of 4, strict options on |
| the tag 1 around the production statement's CWT `iat` | decoded to `datetime` | decoded to `datetime` |
| pycose 1.1.0 reads back its own message (control) | yes | **no**, `TypeError: Bytes cannot be decoded as COSE message` |
| pycose verifies the three receipts over the recomputed root | yes, 3 of 3 | NOT MEASURABLE, control failed |

The pycose failure under cbor2 6 has a measured cause: pycose 1.1.0 checks
`isinstance(cose_obj, list)` on the content of the tag, and cbor2 6.1.4 returns a `tuple` there.

Version facts read at source on 2026-09-25:

- cbor2: 6.1.4 was the newest release on PyPI on 2026-09-25, uploaded 2026-08-01, MIT, requires
  Python >= 3.10 (https://pypi.org/pypi/cbor2/json). Changelog in the source repository linked from
  https://pypi.org/project/cbor2/ (`docs/versionhistory.rst`, head
  `7f84e3da1b60dcdd696c0d4bbcc7d4b9d0b4a2ff`, 2026-09-21): 5.9.0 (2026-03-22) added `max_depth`
  with default 400 (CVE-2026-26209); 6.0.0 (2026-04-28) is a rewrite in Rust, added
  `allow_indefinite` and `semantic_decoders`, changed the `tag_hook` and `object_hook`
  signatures, and dropped Python 3.9; 6.1.0 (2026-05-12) added `allow_duplicate_keys`, default
  True; 6.1.4 (2026-08-01) fixed, among others, acceptance of an indefinite-length map whose break
  follows a key without a value.
- pycose: 1.1.0 was the newest release on PyPI on 2026-09-25, uploaded 2023-12-15, BSD 3-Clause,
  `requires_dist` names `cbor2` without a bound (https://pypi.org/pypi/pycose/json). The source repository linked from
  https://pypi.org/project/pycose/ has its last commit on 2025-10-09
  (`1458ddf14efffbd00bc4052d9026b63da725098e`) and no tag after `v1.1.0`.

## WHERE AN OWN STATEMENT COULD BE REGISTERED

Documentation only. Nothing was registered, no account was created, no service was contacted
beyond reading public repositories.

| option | log type | what it needs | source, retrieved 2026-09-25 |
|---|---|---|---|
| self-hosted scitt-ccf-ledger, *virtual* mode (no TEE) | CCF (`CCF_LEDGER_SHA256`, the same registration code as measured above) | Docker and Python on Linux; `./docker/build.sh`, `./docker/run-dev.sh`, then `scitt submit … --development --url https://localhost:8000 --transparent-statement output.cose`; no account | https://github.com/microsoft/scitt-ccf-ledger/blob/00101f769d872711356e080fbb089ac48589c60a/README.md |
| an Azure Confidential Ledger instance with a SCITT service, like the one that issued the receipts above | CCF (measured: vds 2) | an Azure subscription, so an account; not pursued | https://github.com/microsoft/scitt-verifier/blob/bd6fb8ba79dbb521257b7f09682c03c6681dc3d0/corpus/README.md (the fixtures were registered with `corpus/tools/generate_fixtures.py --ledger mst-test-scitt-verifier.confidential-ledger.azure.com`) |
| Microsoft Signing Transparency, production ledger | CCF (measured on the sample receipt: vds 2, issuer `esrp-cts-cp.confidential-ledger.azure.com`) | whether third parties can register at all is NOT MEASURED: the documentation (https://learn.microsoft.com/en-us/azure/confidential-ledger/about-microsoft-signing-transparency-ledger) is blocked here and was only seen as a search result title | search result, 2026-09-25 |
| DataTrails SCITT API (preview) | **not CCF**: MMRIVER receipts, a Merkle mountain range proof format from an individual COSE draft, vds 3 in the sample code | client id and secret (`DATATRAILS_CLIENT_ID`, `DATATRAILS_CLIENT_SECRET`), so an account; endpoint `POST https://app.datatrails.ai/archivist/v1/publicscitt/entries` in the samples; the leaf includes data beyond the signed statement, per the samples' own note | https://github.com/datatrails/datatrails-scitt-samples/tree/d2d66c5e807b66202d1c471a0a26ba60190c15c9 (last commit 2024-12-12; the current service documentation at docs.datatrails.ai is blocked here, so its present state is NOT MEASURED) |

Only the first option yields a CCF receipt for an own statement without an account. It would
also close the gaps listed under the measured rule (detached payload, non-shortest heads), because
the operator controls what is submitted. That is an owner decision, see ADR 0009.

## REGISTERED HERE: A LOCAL scitt-ccf-ledger (owner answer Q6 a)

`local_ledger_probe.py` registers eight forms of one statement on a scitt-ccf-ledger run locally, in
virtual mode (no TEE, no account), and records what the service did with each. Run on 2026-09-25,
twice with fresh keys, same outcome; the second run is recorded in `local_ledger_result.json`.

The service:

- source: https://github.com/microsoft/scitt-ccf-ledger at `00101f769d872711356e080fbb089ac48589c60a`
- image built here from its `docker/Dockerfile`; the only change is that the base image carries
  this sandbox's proxy CA so the build could download through it
- CCF 7.0.17, RPM sha256 `789d00bed342b08e468a7397f103881df5b6a75c09f3ccc507e2b78a4735fc2e`,
  `reproduce.json` sha256 `6c568e8baa6f5426bbc5fd5ecabc76dd7399658b8b223e7e3581d881b2ab078f`
  (the image's own `build-inputs.json`)
- one node, `cchost` in Docker on 127.0.0.1:8000, opened with the repository's own
  `scitt governance local_development`: unauthenticated registration allowed, policy "any statement
  with a CWT issuer"
- signer made for the run: a P-256 CA and leaf with the extensions the ledger's own client gives its
  test certificates, `did:x509` issuer pinned to the CA; the private key is not written anywhere
- payload: the RFC 8785 root of `examples/example_bundle.json`,
  `df6557c0af226ef3e18e2694c7d6b153343495bc9b6f459f6858e7276ea0fac9`

| form submitted | service | data-hash in the receipt equals |
|---|---|---|
| control: tagged, definite, shortest, embedded payload, empty unprotected | accepted | SHA-256 of the submitted bytes |
| payload detached (nil) | refused: "Detached or empty payloads are not supported" | n/a |
| untagged | refused: "COSE_Sign1 is not tagged" | n/a |
| outer array indefinite | refused: "Signature verification failed" | n/a |
| payload as an indefinite-length byte string | refused: "Detached or empty payloads are not supported" | n/a |
| signature head non-shortest (`59 00 40`) | accepted, stored re-encoded in shortest form | the stored, re-encoded bytes, not the submitted ones |
| unprotected map with label 99 | accepted, stored with the map emptied | the emptied form |
| alg -7 as `38 06` inside the protected header | accepted, protected header kept as sent | the submitted bytes |

Every accepted form's receipt verifies with the key set the service serves at
`/.well-known/scitt-keys`. The control, the non-shortest signature head and the extra unprotected
label are three submissions with **one** data-hash: the service hashes its own re-serialisation.

The control is the first end-to-end ADR 0009 v1 control on real bytes. `--vector-out` wrote it,
with the service key set, the signer's SPKI and the three accepted variants, to
`tests/fixtures/scitt_ccf/local_ledger_control.json`; `proofbundle.scitt_ccf` confirms it, and
refuses the protected-header variant in its pre-scan (ADR 0009, question N1).

## AGAINST THE RUST VERIFIER (owner answer Q7 c)

`rust_crosscheck.py` runs microsoft/scitt-verifier 0.4.0, built with
`cargo build --release --locked -p scitt-verifier` at `bd6fb8ba79dbb521257b7f09682c03c6681dc3d0`
(cargo and rustc 1.94.1), offline with local key sets, on twelve real statements: the eight
fetched ones and the four the local ledger served. The production trust store is turned into a
COSE_KeySet for it (EC2, kid = hex(SHA-256(SPKI))). Per receipt and statement it compares the Merkle
root, the leaf data-hash, the recomputed data-hash, the receipt signature, the binding and the kid
binding against `proofbundle.scitt_ccf`. Recorded in `rust_crosscheck.json`, 2026-09-25:

- 58 values agree, 0 differ
- 9 not comparable, all where v1 refuses a form scitt-verifier reads: the nested tag-18 statement,
  the non-shortest protected header, the legacy receipt, and two kid bindings not reported for an
  invalid signature
- verdicts are recorded, not compared: scitt-verifier appraises a signer chain and a policy, v1
  requires an RFC 9995 hash envelope over a proofbundle root

## CONSISTENCY RECEIPTS, -05 SECTION 4

Measured on 2026-09-25 for the focused last call on section 4; the findings, with every MUST as a row
and every gap as sentence, measurement and question, are in `SECTION4_WGLC.md`.

- No code measured emits a consistency receipt: CCF 7.0.17, CCF main at `9f9ba74b` (2026-09-25),
  scitt-ccf-ledger at `00101f76` (its main).
- What is real: three signed states of one local ledger per run, each with its inclusion receipt, and
  the ledger's own leaves, read from its files with the ccf package 7.0.17 (PyPI, Apache-2.0), whose
  validator checks every root signature. The consistency receipt is the service's own COSE_Sign1 over
  the newer root with a proof computed here from those leaves.
- Third-party oracle: https://github.com/transparency-dev/merkle at
  `fbbcd741c3d1c69d8498487baa8edc9e5824847c` (Apache-2.0), `testonly.Tree` and
  `proof.VerifyConsistency` with CCF's hashing, driven by `rfc9162_oracle.go`, built offline from a
  clone at that commit.
- Exhaustive, every pair up to 257 leaves: 32896 canonical proofs equal RFC 9162 and start with a
  right sibling; 31871 proofs with a deeper anchor, over 16384 distinct pairs, fold to both expected
  roots with the 4.2 algorithm and start with a left one. That is the fold alone, not a receipt and
  not a signature check; full acceptance is measured on the one constructed 22-to-24 receipt.
- Oracle, every pair up to 64 leaves: 2016 of 2016 equal, 1824 of 1824 deeper-anchor proofs, over
  992 distinct pairs, rejected.
- The verifier is `proofbundle.scitt_ccf.verify_consistency_receipt`, with its own status set; the
  run-2 states are committed as `tests/fixtures/scitt_ccf/local_ledger_consistency.json`.
- `consistency_issuer_mismatch` is proofbundle's own rule, not a requirement of -05: the older root
  must come from a receipt of the same issuer. -05 binds the receipt to an older root the verifier
  has already verified (4.2, 7.3) and does not say which trust rule authorizes the receipt's signer,
  including a successor network with a distinct identity under 7.2 (`SECTION4_WGLC.md`, G3); the
  rule stays proofbundle's own policy until the working group answers (owner answer S1 a).

## NOT MEASURED, NOT MEASURABLE

- NOT MEASURED: the published RFC texts and the IETF archive copy of -05 (hosts blocked); the WG
  sources were read instead.
- NOT MEASURED: that the pinned key set is what the live service serves now (hosts blocked).
- NOT MEASURABLE here: the production receipt's signature (no reachable trust material) and its
  binding (statement not published).
- Measured since the first version of this file: the forms that were NOT MEASURABLE without
  registering (non-shortest heads, indefinite lengths, a detached payload, other unprotected
  parameters), on a local ledger; see above. What a production service does with them is still
  NOT MEASURED.
- NOT MEASURED: the CCF version of the services that issued the receipts.
- NOT MEASURABLE here: the artifact behind the production statement's SHA-384 payload (not
  published), so value 1 of that statement is measured for its structure only.
- Measured since: an end-to-end v1 control on real bytes, from the local ledger. It is our own
  registration, on a service attested by nothing; NOT MEASURED on a production service.
- NOT MEASURED: any COSE reader beyond cbor2 5.9.0, cbor2 6.1.4, pycose 1.1.0 and
  microsoft/scitt-verifier 0.4.0.
- The library tests live under `tests/` (`test_scitt_ccf_profile.py`, `test_cbor_prescan.py`,
  `test_scitt_ccf_without_extra.py`, `test_scitt_ccf_external_bytes.py`); the last one reads the
  committed third-party JSON fixtures, so CI runs it (owner answer N3 b).

## REPRODUCING

    python3 fetch_external.py            # network, or: --from-clone scitt-verifier=PATH
                                         #              --from-clone scitt-ccf-ledger=PATH
                                         #              --from-clone ccf-profile=PATH
                                         # --write-fixtures also rewrites the two JSON fixtures
    python3 recompute.py                 # standard library + cryptography, offline
    python3 reader_crosscheck.py         # once per environment: cbor2 6.1.4 + pycose 1.1.0,
                                         # then cbor2 5.9.0 + pycose 1.1.0
    python3 local_ledger_probe.py --service-cert CERT --ledger-commit SHA \
        --build-inputs FILE --vector-out ../../tests/fixtures/scitt_ccf/local_ledger_control.json
                                         # needs a scitt-ccf-ledger running and opened, see above
    python3 rust_crosscheck.py --verifier-clone PATH   # a scitt-verifier checkout at the pin
    python3 consistency_probe.py register --service-cert CERT --out RUN   # a ledger running, as above
    docker cp CONTAINER:/host/node/ledger LEDGER                           # the ledger's own files
    python3 consistency_probe.py leaves --ledger-dir LEDGER --out RUN/leaves.json   # needs ccf==7.0.17
    python3 consistency_probe.py measure --run RUN --leaves RUN/leaves.json \
        --tdev-merkle-clone PATH --vector-out ../../tests/fixtures/scitt_ccf/local_ledger_consistency.json
    python3 consistency_probe.py exhaustive --max-n 257 --tdev-merkle-clone PATH    # needs go
    python3 differential_corpus.py run --service-cert CERT --ledger-commit SHA --image-id ID \
        --build-inputs FILE                          # a ledger running and opened, as above
    python3 differential_corpus.py derive --check    # offline: the summaries are derived from the bytes

`fetch_external.py` exits 1 on a digest mismatch and 2 when a source is unreachable; the other
two exit 2 when the fetched files are missing.

## FILES

| file | |
|---|---|
| `fetch_external.py` | fetches the fifteen files and the two licence files at the pinned commits, checks size and sha256, and with `--write-fixtures` writes the labelled JSON fixtures of the MIT sources |
| `recompute.py` | the four values, the candidate rules, the receipts, the probes; writes `recompute_result.json` |
| `reader_crosscheck.py` | cbor2 and pycose facts per environment; writes `reader_crosscheck.json` |
| `recompute_result.json` | the recorded run of 2026-09-25 |
| `reader_crosscheck.json` | the recorded runs of 2026-09-25, cbor2 5.9.0 and 6.1.4 |
| `local_ledger_probe.py` | registers eight statement forms on a local scitt-ccf-ledger, records what the service does |
| `local_ledger_result.json` | the recorded run of 2026-09-25 |
| `rust_crosscheck.py` | runs microsoft/scitt-verifier at its pin offline and compares with `proofbundle.scitt_ccf` |
| `rust_crosscheck.json` | the recorded run of 2026-09-25 |
| `consistency_probe.py` | -05 section 4: registers three states, reads the ledger's leaves with the ccf package, measures the variants, runs the oracle and the exhaustive check |
| `rfc9162_oracle.go` | the driver of the third-party RFC 9162 oracle, built by `consistency_probe.py` |
| `consistency_result.json` | the recorded runs of 2026-09-25 (run 2 and the exhaustive check) |
| `SECTION4_WGLC.md` | section 4 read rule by rule, the measurements, and the gaps as questions |
| `differential_corpus.py` | a control and one-variable mutations in six classes, registered on a local ledger; the chain per accepted vector, refusals in an admissibility matrix |
| `differential_corpus/` | the recorded run of 2026-09-26 as raw hex text: `vectors/<id>/` holds request, receipt, returned statement and `record.json`; `summary.json` and `admissibility.json` are derived by `differential_corpus.py derive` |
| `.gitignore` | keeps `fetched/` out of the repository |

---

Prepared with AI agent involvement, reviewed and submitted under human oversight.
