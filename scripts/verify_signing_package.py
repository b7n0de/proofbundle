#!/usr/bin/env python3
"""Verify a signing package OFFLINE, before and after the signature is made.

WHAT THIS IS FOR. A release that signs artefacts produces, for each of them, two files: the BODY
(``<name>.body.json``, readable JSON) and the CANONICAL BYTES (``<name>.payload.bin``, exactly what
the signature runs over). The second file is what gets signed. This tool answers the two questions
that have to be asked around that act:

  before  Does what I am about to sign match what I can read? And does it bind the candidate I mean
          to release -- commit, tree digest, distribution digests?
  after   Does my signature verify over exactly those bytes, with exactly my key?

WHY NOT SIMPLY BELIEVE THE MANIFEST. A manifest that confirms its own digests says nothing: it was
produced on the same machine as the files it describes. This tool recomputes every digest and, when
a canonicalizer is available, re-derives the payload bytes FROM THE BODY. Only then is "what I read
is what I sign" measured rather than asserted.

THREE STATES, NOT TWO. If the derivation cannot be recomputed here (no canonicalizer) or a signature
cannot be checked (no `cryptography`), the answer is NOT MEASURABLE -- exit code 2. That is not a
pass. A tool that quietly downgrades "could not check" to "fine" is worse than no tool, because the
reader stops looking.

NOTHING ABOUT A PARTICULAR RELEASE IS BUILT IN. The anchor key, the manifest name and the expected
head are parameters. A package that wants a stricter policy -- a specific gate verdict, an owner
decision, a measurement surface -- carries that policy in its own runner; this tool checks the
package's internal consistency and the signature, which is what every signing package needs.

Manifest shape (JSON):

    {
      "anchor":    {"public_key_b64": "...", "role": "...", "not_after": "..."},
      "candidate": {"commit": "...", "tree_digest": "...",
                    "sdist_sha256": "...", "wheel_sha256": "..."},
      "artifacts": [
        {"name": "...", "body": "<file>", "payload": "<file>",
         "body_sha256": "...", "payload_sha256": "...", "target_rel": "...",
         "kind": "receipt" | "statement",        # "receipt" uses the compact nine-field form
         "binds_candidate": true | false}
      ]
    }

Usage:
    python3 scripts/verify_signing_package.py before --package <dir> [--expected-head <sha>]
    python3 scripts/verify_signing_package.py after  --package <dir> --artifact <name> --signature <file>
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import pathlib
import sys

DEFAULT_MANIFEST = "MANIFEST.json"
#: A file the producer leaves behind while a step is still running. Its presence means the package
#: is incomplete, and an incomplete package must never be signed.
IN_PROGRESS_MARKER = ".step_running"


def _canonicalizer():
    """(function, source) or (None, reason). Two ways to the same standard, RFC 8785."""
    try:
        import rfc8785  # noqa: PLC0415
        return rfc8785.dumps, "rfc8785"
    except ImportError:
        pass
    try:
        from proofbundle import canonical  # noqa: PLC0415
        return canonical.canonicalize_statement, "proofbundle.canonical"
    except ImportError as exc:
        return None, f"neither rfc8785 nor proofbundle importable ({exc})"


def _receipt_payload():
    """The compact nine-field form of a pre-tag receipt, IMPORTED, never copied.

    The house tool this grew out of carried its own copy of the nine field names, and its comments
    already recorded the cost: three copies of one list, and a verifier that recomputes the wrong
    shape when they drift. Importing makes drift impossible instead of detectable.
    """
    try:
        sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
        from pre_tag_receipt_lib import canonical_bytes  # noqa: PLC0415
        return canonical_bytes, "pre_tag_receipt_lib.canonical_bytes"
    except ImportError as exc:
        return None, f"pre_tag_receipt_lib not importable ({exc})"


def _ed25519_verifier():
    try:
        from cryptography.exceptions import InvalidSignature  # noqa: PLC0415
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: PLC0415
            Ed25519PublicKey)
    except ImportError as exc:
        return None, f"cryptography not importable ({exc})"

    def verify(pub_b64: str, sig_b64: str, data: bytes) -> bool:
        pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(pub_b64))
        try:
            pub.verify(base64.b64decode(sig_b64), data)
            return True
        except InvalidSignature:
            return False
    return verify, "cryptography"


def _sha256(p: pathlib.Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def load_manifest(package: pathlib.Path, name: str = DEFAULT_MANIFEST) -> dict:
    """The manifest, or a stated reason to stop. Every failure here is a finding, not a traceback:
    a broken package is a result, and the reader needs the result, not a stack."""
    marker = package / IN_PROGRESS_MARKER
    if marker.exists():
        raise SystemExit(f"STOP: {marker.name} is present ({marker.read_text(encoding='utf-8').strip()}): "
                         "a producing step did not finish, so the package is incomplete. Do not sign.")
    p = package / name
    if not p.is_file():
        raise SystemExit(f"STOP: {p.name} is missing -- without a manifest it is not known what belongs "
                         "to the package, and 'whatever lies here' is not a set.")
    try:
        m = json.loads(p.read_text(encoding="utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise SystemExit(f"STOP: {p.name} is not readable JSON ({exc}) -- the package is damaged. Do not sign.")
    if not isinstance(m, dict) or not isinstance(m.get("artifacts"), list):
        raise SystemExit(f"STOP: {p.name} carries no artifact list. Do not sign.")
    if not m["artifacts"]:
        # AN EMPTY LIST IS NOT A CLEAN PACKAGE, IT IS AN UNCHECKED ONE. Measured on 2026-09-22
        # after a foreign-family review raised the class: with no artefacts the loop below never
        # runs, nothing is found, nothing is unmeasurable, and the tool printed "everything checked
        # and consistent" with exit 0 over a package it had not looked into. A verdict that says
        # "fine" about nothing is the failure mode this whole tool exists to refuse.
        raise SystemExit(f"STOP: {p.name} lists no artefacts at all -- there is nothing to check, "
                         "and 'nothing to check' is not 'everything is fine'.")
    return m


def before(package: pathlib.Path, manifest_name: str = DEFAULT_MANIFEST,
           expected_head: str | None = None, anchor_pubkey: str | None = None) -> int:
    m = load_manifest(package, manifest_name)
    canon, canon_source = _canonicalizer()
    receipt_payload, receipt_source = _receipt_payload()
    findings = 0
    not_measurable = 0

    print("# Offline verification of a signing package, BEFORE the signature")
    print(f"# package       : {package}")
    cand = m.get("candidate") or {}
    print(f"# candidate     : {cand.get('commit', '(no candidate head in the manifest)')}")
    for field in ("tree_digest", "sdist_sha256", "wheel_sha256"):
        if cand.get(field):
            print(f"#   {field:<12}: {cand[field]}")
    print(f"# canonicalizer : {canon_source}")
    print(f"# receipt form  : {receipt_source}")

    anchor = (m.get("anchor") or {}).get("public_key_b64")
    if anchor_pubkey is None:
        print("# anchor key    : NOT checked against an independent source. Without --anchor-pubkey this")
        print("#                 tool only compares the manifest with itself. Pass the key you know.")
    elif anchor != anchor_pubkey:
        print(f"# anchor key    : {anchor!r} DIFFERS from the key you passed ({anchor_pubkey}) -- do not sign")
        findings += 1
    else:
        print(f"# anchor key    : {anchor} (matches the key you passed)")

    if expected_head:
        print(f"# expected head : {expected_head} (independent, from you)")
    else:
        print("# expected head : NOT checked. Without --expected-head this tool compares producer values")
        print("#                 with producer values. Fetch the head yourself, e.g. git ls-remote.")
    print()

    for a in m["artifacts"]:
        name = a["name"]
        body_p = package / a["body"]
        pay_p = package / a["payload"]
        print(f"## {name}")
        if a.get("target_rel"):
            print(f"   target in repo: {a['target_rel']}")
        for role, p, expected in (("body", body_p, a.get("body_sha256")),
                                  ("payload", pay_p, a.get("payload_sha256"))):
            if not p.is_file():
                print(f"   {role:<8} MISSING: {p.name}")
                findings += 1
                continue
            actual = _sha256(p)
            ok = actual == expected
            print(f"   {role:<8} {p.name}  {p.stat().st_size} B  sha256 {actual[:16]}...  "
                  f"{'matches the manifest' if ok else 'DIFFERS from the manifest'}")
            if not ok:
                findings += 1

        if body_p.is_file():
            body = json.loads(body_p.read_text(encoding="utf-8"))
            binds = a.get("binds_candidate", True)
            if binds:
                c = body.get("candidate") or {}
                same = all(c.get(f) == cand.get(f) for f in
                           ("commit", "tree_digest", "sdist_sha256", "wheel_sha256") if cand.get(f))
                print(f"   candidate {'matches the package head' if same else 'DIFFERS from the package head'}")
                if not same:
                    findings += 1
                    for f in ("commit", "tree_digest", "sdist_sha256", "wheel_sha256"):
                        if cand.get(f) and c.get(f) != cand.get(f):
                            print(f"            {f}: body {str(c.get(f))[:16]}... vs head {str(cand.get(f))[:16]}...")
                if expected_head and c.get("commit") != expected_head:
                    print(f"            candidate.commit {str(c.get('commit'))[:16]}... is NOT the expected head "
                          f"{expected_head[:16]}... -- DIFFERS")
                    findings += 1
            else:
                # THE OTHER DIRECTION IS THE HARD ONE. An artefact the manifest says does NOT bind a
                # candidate must not carry half a candidate block either: that would be a binding
                # nobody checks, which is the exact shape this tool exists to refuse.
                print("   candidate: the manifest says this artefact binds no candidate")
                if body.get("candidate"):
                    print("            BUT it carries a candidate block -- a binding nobody checks does not "
                          "belong in an artefact.")
                    findings += 1
                if not body.get("version"):
                    print("            AND it carries no version field -- then it binds nothing at all.")
                    findings += 1
            for key in ("signature", "signer_pubkey"):
                if key in body:
                    print(f"            the body already carries {key} -- nothing may be signed over that.")
                    findings += 1

        is_receipt = a.get("kind") == "receipt"
        tool = receipt_payload if is_receipt else canon
        if not body_p.is_file() or not pay_p.is_file() or tool is None:
            why = (receipt_source if is_receipt and receipt_payload is None
                   else canon_source if tool is None else "a file is missing")
            print(f"   derivation NOT MEASURABLE ({why}) -- the digests above were checked, the equality "
                  "body -> payload was NOT.")
            not_measurable += 1
        else:
            body = json.loads(body_p.read_text(encoding="utf-8"))
            without = {k: v for k, v in body.items() if k != "signature"}
            derived = tool(body) if is_receipt else tool(without)
            stored = pay_p.read_bytes()
            if derived == stored:
                print(f"   derivation body -> payload BYTE IDENTICAL ({len(stored)} B) -- what you read is "
                      "what you sign.")
            else:
                print(f"   derivation DIFFERS: {len(derived)} B from the body, {len(stored)} B in the payload. "
                      "Do not sign.")
                findings += 1
        print()

    if findings:
        print(f"VERDICT: {findings} finding(s) -- do not sign until they are resolved")
        return 1
    if not_measurable:
        print(f"VERDICT: NOT MEASURABLE -- for {not_measurable} artefact(s) the equality body -> payload could")
        print("         not be recomputed here (no canonicalizer, or a file is missing). That is not a pass:")
        print("         install rfc8785 and cryptography, run 'before' again, and only then sign.")
        return 2
    print("VERDICT: everything checked and consistent")
    return 0


def after(package: pathlib.Path, artifact: str, signature_file: pathlib.Path,
          manifest_name: str = DEFAULT_MANIFEST, anchor_pubkey: str | None = None) -> int:
    m = load_manifest(package, manifest_name)
    a = next((x for x in m["artifacts"] if x["name"] == artifact), None)
    if a is None:
        raise SystemExit(f"STOP: {artifact!r} is not in the manifest. Present: "
                         f"{[x['name'] for x in m['artifacts']]}")
    verify, crypto_source = _ed25519_verifier()
    payload = (package / a["payload"]).read_bytes()
    sig_b64 = signature_file.read_text(encoding="utf-8").strip()
    pub_b64 = (m.get("anchor") or {}).get("public_key_b64")

    print("# Offline verification, AFTER the signature")
    print(f"# artefact : {artifact}")
    print(f"# payload  : {a['payload']}  {len(payload)} B  sha256 {hashlib.sha256(payload).hexdigest()}")
    print(f"# verifier : {crypto_source}")
    if anchor_pubkey is None:
        # SELF-ATTESTATION, SAID OUT LOUD. Without a key from outside this package, the check is
        # "the signature matches the key the package itself names" -- which any producer of the
        # package can satisfy, including one who swapped both. The `before` path already said this;
        # leaving it unsaid here was an inconsistency a foreign-family review pointed at.
        print("# anchor   : NOT checked against an independent source. This run only shows that the")
        print("#            signature matches the key THE PACKAGE NAMES. Pass --anchor-pubkey to")
        print("#            check it against a key you know from somewhere else.")
    if anchor_pubkey is not None and pub_b64 != anchor_pubkey:
        print(f"VERDICT: the manifest's anchor key {str(pub_b64)[:16]}... is NOT the key you passed -- "
              "the signature was not checked against your key.")
        return 1
    if verify is None:
        print("VERDICT: NOT MEASURABLE -- without cryptography the signature cannot be checked here. "
              "That is not a pass.")
        return 2
    ok = verify(pub_b64, sig_b64, payload)
    print(f"VERDICT: the signature {'VERIFIES' if ok else 'DOES NOT VERIFY'} over exactly these bytes "
          f"with the anchor key {str(pub_b64)[:16]}...")
    if not ok:
        return 1

    target = package / f"{artifact}.signed.json"
    body = json.loads((package / a["body"]).read_text(encoding="utf-8"))
    if a.get("kind") == "receipt":
        # A receipt carries the signature as a STRING plus signer_pubkey; a statement carries the
        # structured block. Writing the wrong one produces a file that the gate rejects, and the
        # rejection would look like a bad signature rather than a bad assembly.
        body["signature"] = sig_b64
        body["signer_pubkey"] = pub_b64
    else:
        body["signature"] = {"alg": "ed25519", "public_key_b64": pub_b64, "sig_b64": sig_b64}
    target.write_text(json.dumps(body, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"         PREVIEW assembled -> {target.name} ({target.stat().st_size} B, sha256 "
          f"{_sha256(target)[:16]}...). This is a preview, not the artefact for the repository: the")
    print("         producer assembles that one and verifies the signature itself while doing so.")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="mode", required=True)
    b = sub.add_parser("before", help="check the package before signing")
    a = sub.add_parser("after", help="check a signature after signing")
    for q in (b, a):
        q.add_argument("--package", type=pathlib.Path, default=pathlib.Path("."),
                       help="the package directory (default: the current one)")
        q.add_argument("--manifest", default=DEFAULT_MANIFEST, help=f"manifest name (default: {DEFAULT_MANIFEST})")
        q.add_argument("--anchor-pubkey", default=None,
                       help="the base64 Ed25519 public key you expect, from a source that is not this package")
    b.add_argument("--expected-head", default=None,
                   help="the candidate head (40 hex) from an INDEPENDENT source, e.g. git ls-remote")
    a.add_argument("--artifact", required=True)
    a.add_argument("--signature", required=True, type=pathlib.Path)
    ns = p.parse_args(argv)
    if ns.mode == "before":
        return before(ns.package, ns.manifest, ns.expected_head, ns.anchor_pubkey)
    return after(ns.package, ns.artifact, ns.signature, ns.manifest, ns.anchor_pubkey)


if __name__ == "__main__":
    sys.exit(main())
