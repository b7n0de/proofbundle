#!/usr/bin/env python3
"""Attach, upgrade and verify a time anchor for a receipt this house issues.

Why this exists: measured on 2026-09-12 over the nine receipts of 6.0.0, exactly one
carries a time anchor and it is unconfirmed, and none carries a transparency-log
registration. The pre-tag receipt states its own `produced_at` and nothing witnesses it.
A statement about when something existed, witnessed only by the party making it, is not
evidence. Register entry N22.

Three commands, and the split between them is the point:

  attach   put an anchor next to a receipt. Submitting a commitment to a public calendar
           is OUTWARD-FACING, so it needs --submit; without it the command is a dry run
           that says exactly what it would send (a 32-byte digest, never the content).

  upgrade  a pending attestation is a PROMISE, not an anchor. This fetches the confirmed
           attestation the calendars already hold. It is read-only: a GET for a
           commitment those calendars were given long ago. Nothing new leaves the house.

  verify   check a receipt and its anchor TOGETHER. Three separate questions, never
           collapsed into one boolean: does the proof bind THESE bytes, what kind of
           attestation does it carry, and is it confirmed. A proof can bind correctly
           and still attest nothing.

The verdict vocabulary is deliberately three-valued. `PENDING` is not a weak `OK` — it
is the honest name for "submitted, not yet anchored", and reporting it as OK is the
class this whole register is about: a form that looks like the property.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

try:
    from opentimestamps.core.notary import BitcoinBlockHeaderAttestation, PendingAttestation
    from opentimestamps.core.op import OpSHA256
    from opentimestamps.core.serialize import BytesDeserializationContext, BytesSerializationContext
    from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp
    from opentimestamps.core.timestamp import cat_sha256d  # noqa: F401  (presence check)
except ImportError as exc:  # pragma: no cover - environment, not logic
    print(f"opentimestamps is not importable: {exc}", file=sys.stderr)
    print("canonical surface: PYTHONPATH=src ~/proofbundle/.venv/bin/python", file=sys.stderr)
    raise SystemExit(3)

CALENDARS = (
    "https://a.pool.opentimestamps.org",
    "https://b.pool.opentimestamps.org",
    "https://alice.btc.calendar.opentimestamps.org",
)
OK, PENDING, BROKEN, ABSENT = "OK", "PENDING", "BROKEN", "ABSENT"


def anchor_path(receipt: Path) -> Path:
    """The anchor lives next to the receipt, name plus suffix — never inside it.

    Inside would change the bytes the anchor commits to, which is a fixed point nobody
    can hold: writing the proof changes the digest the proof is about.
    """
    return receipt.with_name(receipt.name + ".ots")


def _walk(timestamp, msg):
    """Yield (attestation, commitment) for every leaf, following the ops."""
    for att in timestamp.attestations:
        yield att, msg
    for op, sub in timestamp.ops.items():
        yield from _walk(sub, op(msg))


def read_proof(path: Path):
    ctx = BytesDeserializationContext(path.read_bytes())
    return DetachedTimestampFile.deserialize(ctx)


def verify(receipt: Path) -> dict:
    """Three questions, three answers. Never one boolean."""
    ap = anchor_path(receipt)
    out = {
        "receipt": str(receipt),
        "anchor": str(ap),
        "receipt_sha256": hashlib.sha256(receipt.read_bytes()).hexdigest(),
        "verdict": ABSENT,
        "binds_these_bytes": None,
        "attestations": {},
        "confirmed_height": None,
        "reason": "",
    }
    if not ap.is_file():
        out["reason"] = "no anchor file next to the receipt"
        return out
    try:
        dt = read_proof(ap)
    except Exception as exc:
        out["verdict"] = BROKEN
        out["reason"] = f"anchor is not a readable OTS proof: {type(exc).__name__}: {exc}"
        return out

    # Question 1: does the proof bind THESE bytes? A tampered proof fails here.
    digest_in_proof = dt.file_digest.hex()
    out["digest_in_proof"] = digest_in_proof
    out["binds_these_bytes"] = digest_in_proof == out["receipt_sha256"]
    if not out["binds_these_bytes"]:
        out["verdict"] = BROKEN
        out["reason"] = (
            f"the proof binds {digest_in_proof[:16]}… but the receipt hashes to "
            f"{out['receipt_sha256'][:16]}… — this anchor is about other bytes"
        )
        return out

    # Question 2: what kind of attestation, and 3: is any of them confirmed?
    kinds: dict[str, int] = {}
    height = None
    for att, _msg in _walk(dt.timestamp, dt.timestamp.msg):
        name = type(att).__name__
        kinds[name] = kinds.get(name, 0) + 1
        if isinstance(att, BitcoinBlockHeaderAttestation):
            height = att.height if height is None else min(height, att.height)
    out["attestations"] = kinds
    out["confirmed_height"] = height
    if height is not None:
        out["verdict"] = OK
        out["reason"] = f"anchored in a bitcoin block header at height {height}"
    elif kinds.get("PendingAttestation"):
        out["verdict"] = PENDING
        out["reason"] = (
            f"{kinds['PendingAttestation']} calendar promise(s), no block attestation — "
            "submitted, NOT anchored; run `upgrade`"
        )
    else:
        out["verdict"] = BROKEN
        out["reason"] = "the proof carries no attestation at all"
    return out


def _post_calendar(url: str, digest: bytes, timeout: int) -> Timestamp | None:
    req = urllib.request.Request(
        f"{url}/digest", data=digest,
        headers={"Accept": "application/vnd.opentimestamps.v1",
                 "User-Agent": "proofbundle-receipt-anchor",
                 "Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        body = urllib.request.urlopen(req, timeout=timeout).read()
    except Exception as exc:
        print(f"  {url}: NOT MEASURED ({type(exc).__name__}: {exc})", file=sys.stderr)
        return None
    ctx = BytesDeserializationContext(body)
    ts = Timestamp(digest)
    ts.deserialize(ctx, digest)
    print(f"  {url}: {len(body)} B")
    return ts


def attach(receipt: Path, submit: bool, timeout: int) -> int:
    digest = hashlib.sha256(receipt.read_bytes()).digest()
    ap = anchor_path(receipt)
    if ap.exists():
        print(f"an anchor already exists: {ap}. Refusing to overwrite — use `upgrade`.")
        return 1
    if not submit:
        print("DRY RUN — nothing was sent. With --submit this would post:")
        print(f"  {digest.hex()}   (32 bytes, the sha256 of {receipt.name})")
        print(f"  to: {', '.join(CALENDARS)}")
        print("The calendars receive a digest, never the content. The anchor would be")
        print(f"  written to {ap}")
        return 0
    print(f"submitting the digest of {receipt.name} to {len(CALENDARS)} calendars:")
    merged: Timestamp | None = None
    for url in CALENDARS:
        ts = _post_calendar(url, digest, timeout)
        if ts is None:
            continue
        if merged is None:
            merged = ts
        else:
            merged.merge(ts)
    if merged is None:
        print("no calendar answered — NOT MEASURED, no file written", file=sys.stderr)
        return 2
    ctx = BytesSerializationContext()
    DetachedTimestampFile(OpSHA256(), merged).serialize(ctx)
    ap.write_bytes(ctx.getbytes())
    print(f"wrote {ap} ({ap.stat().st_size} B) — verdict is PENDING until `upgrade` finds a block")
    return 0


def upgrade(receipt: Path, timeout: int) -> int:
    """Read-only: fetch the confirmation the calendars already hold."""
    ap = anchor_path(receipt)
    if not ap.is_file():
        print(f"no anchor at {ap}", file=sys.stderr)
        return 1
    dt = read_proof(ap)
    pending = [(att, msg) for att, msg in _walk(dt.timestamp, dt.timestamp.msg)
               if isinstance(att, PendingAttestation)]
    if not pending:
        print("no pending attestation — nothing to upgrade")
        return 0
    print(f"{len(pending)} pending attestation(s):")
    got = 0
    for att, msg in pending:
        uri = att.uri.decode() if isinstance(att.uri, bytes) else att.uri
        url = f"{uri}/timestamp/{msg.hex()}"
        try:
            body = urllib.request.urlopen(url, timeout=timeout).read()
        except urllib.error.HTTPError as exc:
            print(f"  {uri}: HTTP {exc.code} — not confirmed yet")
            continue
        except Exception as exc:
            print(f"  {uri}: NOT MEASURED ({type(exc).__name__})")
            continue
        print(f"  {uri}: {len(body)} B available")
        got += 1
    print(f"\n{got} of {len(pending)} calendars hold a confirmation.")
    print("NOT WRITTEN: merging an upgraded proof needs the calendar's own path format;")
    print("this command reports availability so the gap is measured, not assumed.")
    return 0 if got else 1


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    for name, helptext in (("attach", "put an anchor next to a receipt"),
                           ("upgrade", "fetch a confirmation the calendars already hold"),
                           ("verify", "check receipt and anchor together")):
        sp = sub.add_parser(name, help=helptext)
        sp.add_argument("receipt", type=Path)
        sp.add_argument("--timeout", type=int, default=30)
        if name == "attach":
            sp.add_argument("--submit", action="store_true",
                            help="actually send the digest to the public calendars")
        if name == "verify":
            sp.add_argument("--json", action="store_true")
            sp.add_argument("--require-confirmed", action="store_true",
                            help="exit 1 on PENDING as well, not only on BROKEN/ABSENT")
    a = p.parse_args(argv)
    if not a.receipt.is_file():
        print(f"no such receipt: {a.receipt}", file=sys.stderr)
        return 2
    if a.cmd == "attach":
        return attach(a.receipt, a.submit, a.timeout)
    if a.cmd == "upgrade":
        return upgrade(a.receipt, a.timeout)
    r = verify(a.receipt)
    if a.json:
        print(json.dumps(r, indent=2))
    else:
        print(f"receipt  {r['receipt']}")
        print(f"sha256   {r['receipt_sha256']}")
        print(f"binds    {r['binds_these_bytes']}")
        print(f"attest   {r['attestations'] or '-'}")
        print(f"VERDICT  {r['verdict']}  —  {r['reason']}")
    if r["verdict"] == OK:
        return 0
    if r["verdict"] == PENDING:
        return 1 if a.require_confirmed else 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
