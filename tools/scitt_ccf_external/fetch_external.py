#!/usr/bin/env python3
"""Fetch real CCF based SCITT evidence at pinned commits, and verify every file by size and sha256.

WHAT IS FETCHED. Two public sources, each at a pinned commit:

  * microsoft/scitt-verifier, corpus/fixtures: transparent statements registered on a live
    CCF based transparency service (issuer mst-test-scitt-verifier.confidential-ledger.azure.com),
    the service's COSE_KeySet, a second service's key set, three mutants of the first statement,
    two further registered statements and an RFC 9995 hash envelope with its artifact.
    Licence: MIT (the repository's LICENSE file, Copyright (c) Microsoft Corporation).
  * microsoft/scitt-ccf-ledger, test data: a transparent statement from the production
    Microsoft Signing Transparency ledger (issuer esrp-cts-db.confidential-ledger.azure.com)
    whose signed statement is an RFC 9995 hash envelope, the service trust store it is checked
    against in that repository's own tests, and a statement carrying a receipt in the legacy,
    pre-RFC 9942 form. Licence: MIT (the repository's LICENSE.txt).
  * ietf-wg-scitt/draft-ietf-scitt-receipts-ccf-profile at the commit tagged -05:
    samples/microsoft-mst-receipt.cbor, a receipt issued by the production Microsoft Signing
    Transparency ledger. Licence: contributions to the IETF under BCP 78/79 and the IETF Trust
    Legal Provisions, which is not a plain redistribution grant for a sample file.

WHY A FETCHER AND NOT A COPY. The first source would allow redistribution under MIT with its
notice. The second does not say so plainly. And this repository takes no new binary fixture
files from agent work (AGENTS.md). So neither is vendored; the digests below are the pin and the
address is only transport, as in tools/scitt_ccf_datahash_vector/fetch_upstream_vectors.py.

FAIL-CLOSED. A reachable source that serves bytes of a different size or digest stops the run
and writes nothing. That is a finding, not an outage. An unreachable source is NOT MEASURABLE
and exits 2, never a verdict about the evidence.

A SECOND TRANSPORT. `--from-clone NAME=PATH` reads the files from a local git clone instead of
the network (`git clone` works in some sandboxes where raw file hosts do not). The clone's bytes
are held against the same digests, so the transport changes nothing about what is accepted.

Retrieved and pinned on 2026-09-25.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import sys
import urllib.request
from pathlib import Path

USER_AGENT = "proofbundle-scitt-ccf-external-fetch/1 (+https://github.com/b7n0de/proofbundle)"

#: source name -> (repository, pinned commit)
REPOSITORIES = {
    "scitt-verifier": ("microsoft/scitt-verifier", "bd6fb8ba79dbb521257b7f09682c03c6681dc3d0"),
    "ccf-profile": ("ietf-wg-scitt/draft-ietf-scitt-receipts-ccf-profile",
                    "e729c2ec037ac763d0cf422bb58a219f8d6a02f4"),
    "scitt-ccf-ledger": ("microsoft/scitt-ccf-ledger", "00101f769d872711356e080fbb089ac48589c60a"),
}

#: local file name -> (source name, path in the repository, size in bytes, sha256)
EXPECTED = {
    "transparent-statement.cose": (
        "scitt-verifier", "corpus/fixtures/transparent-statement.cose", 5401,
        "4bb50fe1a92f74cd85405a15508f560f1bfd77a43e1d00d4b3d718cf5d112377"),
    "mst-test-scitt-keys.cbor": (
        "scitt-verifier", "corpus/fixtures/mst-test-scitt-keys.cbor", 175,
        "b146b954b2ba79eec5e59748d96064b5f18dfe4b13f90cf5868207985d6faf0e"),
    "other-service-scitt-keys.cbor": (
        "scitt-verifier", "corpus/fixtures/other-service-scitt-keys.cbor", 523,
        "f113c423176de67543c5f8d55e18c5779506e3ab16d1f3122a4365f7d0301d40"),
    "payload-tampered.cose": (
        "scitt-verifier", "corpus/fixtures/payload-tampered.cose", 5401,
        "0b16482599ab0209bbb2b7cb605e71ab8df823cd865c1c172727ecad239503d1"),
    "tampered-statement.cose": (
        "scitt-verifier", "corpus/fixtures/tampered-statement.cose", 5401,
        "075797b10f73d15f699f907c2ac7150ab87b4afe8d979238d650d497982cec2a"),
    "appended-receipt.cose": (
        "scitt-verifier", "corpus/fixtures/appended-receipt.cose", 5989,
        "871109cfb997a19187df71106c7507abb39171194bf88a722dbdee0f0bdeb56c"),
    "cbor-header.cose": (
        "scitt-verifier", "corpus/fixtures/cbor-header.cose", 3411,
        "78c91991c8a92aa169da7a6e2ad43e5d5c7bd5165d0f306c3fca6af92a5bcb46"),
    "nested-sign1.cose": (
        "scitt-verifier", "corpus/fixtures/nested-sign1.cose", 3353,
        "9f04814fd5d21c4e921c72369d3b68ed01cdeef4dfed00965160dd56c88c42c1"),
    "hash-envelope.cose": (
        "scitt-verifier", "corpus/fixtures/hash-envelope.cose", 702,
        "4a16941a117dff754fe5118e72f28bcabf9bda1312f959a0394b92e2073002f7"),
    "hash-envelope-artifact.spdx.json": (
        "scitt-verifier", "corpus/fixtures/hash-envelope-artifact.spdx.json", 57,
        "a3c890a2ef462e1629270e489f7d41ac02c285a556bd411fb58f5aebf9e51ce0"),
    "hash-envelope-bad-artifact.spdx.json": (
        "scitt-verifier", "corpus/fixtures/hash-envelope-bad-artifact.spdx.json", 44,
        "d6e26054fcf7385d419489e4029b751269568d96364cb697f73212fcab550300"),
    "uvm_0.2.10.cose": (
        "scitt-ccf-ledger", "test/transparent_statements/uvm_0.2.10.cose", 6145,
        "f4f5321316ac3cf876292f41cb7bdcd1056aef3a815fb137887a4ef93c3210bc"),
    "esrp-cts-db.json": (
        "scitt-ccf-ledger", "test/transparent_statements/esrp-cts-db.json", 6505,
        "295b5824129179cb6a0699b2759ce408c0fe13b364e7a59ad226a68f7265a490"),
    "cts-hashv-cwtclaims-b64url.cose": (
        "scitt-ccf-ledger", "test/payloads/cts-hashv-cwtclaims-b64url.cose", 5624,
        "213105fdc0da9022c20e8f49195d0bb621cedf87fdee29aad80e2e605af94c87"),
    "microsoft-mst-receipt.cbor": (
        "ccf-profile", "samples/microsoft-mst-receipt.cbor", 725,
        "db2398e1c9d140619e484d277a05eb186d7d78f91c01f49e595f6047b98249f5"),
}


class Mismatch(ValueError):
    """A reachable source served bytes that are not the pinned ones."""


def raw_url(source: str, path: str) -> str:
    repo, commit = REPOSITORIES[source]
    return f"https://raw.githubusercontent.com/{repo}/{commit}/{path}"


def check(name: str, raw: bytes, origin: str) -> bytes:
    _source, _path, size, digest = EXPECTED[name]
    got = hashlib.sha256(raw).hexdigest()
    if len(raw) != size or got != digest:
        raise Mismatch(f"MISMATCH for {name} from {origin}: {len(raw)} B / {got}\n"
                       f"  expected {size} B / {digest}\n  Nothing written.")
    return raw


def fetch_network(name: str, opener=urllib.request.urlopen) -> bytes:
    source, path, _size, _digest = EXPECTED[name]
    url = raw_url(source, path)
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with opener(req, timeout=30) as fh:   # noqa: S310 - fixed https
        return check(name, fh.read(), url)


def fetch_clone(name: str, clones: dict) -> bytes:
    source, path, _size, _digest = EXPECTED[name]
    root = Path(clones[source])
    return check(name, (root / path).read_bytes(), f"{root}/{path}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--out", default=str(Path(__file__).resolve().parent / "fetched"))
    ap.add_argument("--from-clone", action="append", default=[], metavar="SOURCE=PATH",
                    help="read SOURCE (scitt-verifier, scitt-ccf-ledger or ccf-profile) from a "
                         "local clone checked out at the pinned commit")
    args = ap.parse_args(argv)
    clones = {}
    for item in args.from_clone:
        key, _, value = item.partition("=")
        if key not in REPOSITORIES or not value:
            ap.error(f"--from-clone needs SOURCE=PATH with SOURCE in {sorted(REPOSITORIES)}")
        clones[key] = value

    fetched = {}
    for name, (source, _path, _size, _digest) in EXPECTED.items():
        try:
            raw = fetch_clone(name, clones) if source in clones else fetch_network(name)
        except Mismatch as exc:
            print(str(exc), file=sys.stderr)
            return 1
        except OSError as exc:
            print(f"NOT MEASURABLE: {name} could not be read ({exc}). "
                  "This is not a verdict about the evidence.", file=sys.stderr)
            return 2
        fetched[name] = raw

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for name, raw in fetched.items():
        tmp = out / f".{name}.partial"
        tmp.write_bytes(raw)
        os.replace(tmp, out / name)
    for name, raw in fetched.items():
        source = EXPECTED[name][0]
        via = "clone" if source in clones else "network"
        print(f"  {name:38s} {len(raw):5d} B  {hashlib.sha256(raw).hexdigest()[:16]}…  matches"
              f"  ({source} @ {REPOSITORIES[source][1][:12]}, via {via})")
    print(f"All {len(fetched)} files verified against their pinned digests.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
