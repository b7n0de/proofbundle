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
cannot be checked (no `proofbundle.signature`, which needs `cryptography`), the answer is NOT
MEASURABLE -- exit code 2. That is not a pass. A tool that quietly downgrades "could not check" to "fine" is worse than no tool, because the
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
import hashlib
import json
import pathlib
import re
import sys

DEFAULT_MANIFEST = "MANIFEST.json"
#: A file the producer leaves behind while a step is still running. Its presence means the package
#: is incomplete, and an incomplete package must never be signed.
IN_PROGRESS_MARKER = ".step_running"

#: The four fields a candidate binding names. A binding that leaves one out does not bind it. The first
#: version compared only the fields the manifest happened to carry, so an empty `candidate` compared
#: nothing and still printed a match (Codex on pull request 369, round one, P1).
CANDIDATE_FIELDS = ("commit", "tree_digest", "sdist_sha256", "wheel_sha256")

#: An artefact name is a plain name: it becomes part of a file name inside the package and is never a
#: path. It starts with a letter or digit, so `.` and `..` are no names.
_ARTIFACT_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")


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


def _trusted_anchor(pub_b64) -> "tuple[bytes | None, str | None]":
    """The anchor key as the 32 bytes a signature is checked under, judged the way the package judges
    every key a caller trusts: (raw, None) for a key that can stand, (None, why) for one that cannot.
    Raises ImportError when proofbundle is not importable here, which the callers report as NOT
    MEASURABLE.

    THE ANCHOR IS A TRUSTED KEY, so it gets the trust-anchor rule of SPEC section 4b. Under a key of
    small order a signature made with no private key verifies on the bare SPEC section 4a profile, and
    the first version of this tool checked with that profile, so a package whose anchor named such a
    key showed VERIFIES over a signature nobody made. tests/test_release_tooling_refuses_weak_pinned_keys.py
    holds every Ed25519 check under scripts/ to the rule.

    ONE DECODER, the package's. `base64.b64decode` takes a second spelling of the same bytes (a
    character outside the alphabet it drops, a non-zero pad bit), so one key or one signature had more
    than one accepted text (tests/test_lauf11_l2_scripts_dekodieren_strikt.py)."""
    from proofbundle._wire_b64 import decode_b64  # noqa: PLC0415
    from proofbundle.signature import (  # noqa: PLC0415
        TRUST_ANCHOR_REFUSAL,
        ed25519_trust_anchor_weakness,
    )
    if pub_b64 is None:
        return None, "is missing from the manifest (anchor.public_key_b64)"
    try:
        raw = decode_b64(pub_b64)
    except ValueError as exc:
        return None, f"is not canonical base64 ({exc})"
    weakness = ed25519_trust_anchor_weakness(raw)
    if weakness is not None:
        return None, (f"is a {weakness} Ed25519 key, refused as a trusted key: "
                      f"{TRUST_ANCHOR_REFUSAL[weakness]}")
    return raw, None


def _ed25519_verifier():
    """(function, source) or (None, reason). The function answers (ok, why) for an anchor key in
    base64, a signature in base64 and the signed bytes, through `verify_ed25519_pinned`."""
    try:
        from proofbundle._wire_b64 import decode_b64  # noqa: PLC0415
        from proofbundle.signature import verify_ed25519_pinned  # noqa: PLC0415
    except ImportError as exc:
        return None, f"proofbundle.signature not importable ({exc})"

    def verify(pub_b64, sig_b64: str, data: bytes) -> "tuple[bool, str]":
        raw, refusal = _trusted_anchor(pub_b64)
        if raw is None:
            return False, f"the anchor key {refusal}"
        try:
            sig = decode_b64(sig_b64)
        except ValueError as exc:
            return False, f"the signature is not canonical base64 ({exc})"
        if verify_ed25519_pinned(raw, sig, data):
            return True, ""
        return False, "the signature does not verify over these bytes under this key"
    return verify, "proofbundle.signature.verify_ed25519_pinned"


def _sha256(p: pathlib.Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def _inside(package: pathlib.Path, rel, what: str) -> pathlib.Path:
    """A file name the manifest gives, kept inside the package, or a stated reason to stop.

    THE MANIFEST IS PART OF WHAT IS CHECKED, NOT A TRUSTED PARTY. The first version joined every name
    it found there to the package directory. An absolute name or one with `..` replaced or left the
    directory, so `after` read a JSON file from anywhere on the signing machine into the preview, and
    a crafted artefact name wrote the preview outside the package (Codex on pull request 369, round
    one, P1). The name is refused on its form, and then the resolved path, symlinks followed, has to
    lie under the resolved package: a name can stay inside the directory and point out of it.
    """
    if not isinstance(rel, str) or not rel:
        raise SystemExit(f"STOP: {what} is not a file name ({rel!r}). Do not sign.")
    form = pathlib.PurePath(rel)
    if form.is_absolute() or ".." in form.parts:
        raise SystemExit(f"STOP: {what} {rel!r} lies outside the package, and the manifest may only name "
                         "files inside it. Do not sign.")
    full = (package / rel).resolve()
    try:
        full.relative_to(package.resolve())
    except ValueError:
        raise SystemExit(f"STOP: {what} {rel!r} resolves to {full}, which lies outside the package. "
                         "Do not sign.") from None
    return package / rel


def _derived_payload(a: dict, body: dict) -> "tuple[bytes | None, str]":
    """The payload re-derived from the body in the form the artefact's kind prescribes: (bytes, source),
    or (None, why) when the tool for that form is not importable here.

    ONE DERIVATION FOR BOTH PHASES. `before` derived the payload from the body and `after` did not
    derive it at all, so the equality `before` established was never asked again once the signature
    existed (Codex on pull request 369, round one, P1). Both phases call this now.

    A body that cannot take the form raises ValueError or TypeError (a receipt without one of its signed
    fields, a value the canonical form refuses). The callers report that as a finding, not as NOT
    MEASURABLE: the tool was there, the package was wrong.
    """
    if a.get("kind") == "receipt":
        fn, source = _receipt_payload()
        return (fn(body), source) if fn is not None else (None, source)
    fn, source = _canonicalizer()
    if fn is None:
        return None, source
    return fn({k: v for k, v in body.items() if k != "signature"}), source


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
    # EVERY NAME IS CHECKED HERE, ONCE, before any phase reads a file. Checking at each reader would
    # leave the next reader to remember it.
    for a in m["artifacts"]:
        if not isinstance(a, dict):
            raise SystemExit(f"STOP: {p.name} lists an artefact that is not an object ({a!r}). Do not sign.")
        name = a.get("name")
        if not isinstance(name, str) or not _ARTIFACT_NAME.match(name):
            raise SystemExit(f"STOP: the artefact name {name!r} is not a plain name -- it becomes part of a "
                             "file name inside the package and may not be a path. Do not sign.")
        for role in ("body", "payload"):
            _inside(package, a.get(role), f"the {role} of {name!r}")
    return m


def before(package: pathlib.Path, manifest_name: str = DEFAULT_MANIFEST,
           expected_head: str | None = None, anchor_pubkey: str | None = None) -> int:
    m = load_manifest(package, manifest_name)
    _, canon_source = _canonicalizer()
    _, receipt_source = _receipt_payload()
    findings = 0
    not_measurable = 0

    print("# Offline verification of a signing package, BEFORE the signature")
    print(f"# package       : {package}")
    cand = m.get("candidate") or {}
    print(f"# candidate     : {cand.get('commit', '(no candidate head in the manifest)')}")
    for field in CANDIDATE_FIELDS[1:]:
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
    # A KEY NOBODY HOLDS IS NO ANCHOR, and that is decided before anything is signed under it. A
    # matching key passed by the reader says the package names the key the reader meant, not that the
    # key can stand as a trusted one.
    try:
        _raw, refusal = _trusted_anchor(anchor)
    except ImportError as exc:
        print(f"# anchor rule   : NOT MEASURABLE, proofbundle.signature not importable ({exc})")
        not_measurable += 1
    else:
        if refusal:
            print(f"# anchor rule   : the anchor key {refusal} -- do not sign")
            findings += 1
        else:
            print("# anchor rule   : the anchor key can stand as a trusted Ed25519 key (SPEC section 4b)")

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
                # EVERY FIELD, NOT THE ONES THAT HAPPEN TO BE THERE. A field the manifest leaves out is
                # a field nobody binds, and a comparison over no fields is no comparison.
                missing = [f for f in CANDIDATE_FIELDS if not cand.get(f)]
                differ = [f for f in CANDIDATE_FIELDS if cand.get(f) and c.get(f) != cand.get(f)]
                if missing:
                    print(f"   candidate INCOMPLETE: the manifest names no {', '.join(missing)} -- a binding "
                          "that leaves a field out does not bind it")
                    findings += 1
                if differ:
                    print("   candidate DIFFERS from the package head")
                    findings += 1
                    for f in differ:
                        print(f"            {f}: body {str(c.get(f))[:16]}... vs head {str(cand.get(f))[:16]}...")
                if not missing and not differ:
                    print("   candidate matches the package head")
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

        derived, why, broken = None, "a file is missing", None
        if body_p.is_file() and pay_p.is_file():
            try:
                derived, why = _derived_payload(a, json.loads(body_p.read_text(encoding="utf-8")))
            except (ValueError, TypeError) as exc:
                broken = exc
        if broken is not None:
            print(f"   derivation IMPOSSIBLE: the body does not have the form its kind prescribes ({broken}). "
                  "Do not sign.")
            findings += 1
        elif derived is None:
            print(f"   derivation NOT MEASURABLE ({why}) -- the digests above were checked, the equality "
                  "body -> payload was NOT.")
            not_measurable += 1
        else:
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
        print(f"VERDICT: NOT MEASURABLE -- {not_measurable} check(s) could not be made here: the equality")
        print("         body -> payload (no canonicalizer, or a file is missing) or the anchor rule (no")
        print("         proofbundle.signature). That is not a pass: install proofbundle with rfc8785 and")
        print("         cryptography, run 'before' again, and only then sign.")
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
    body_p = _inside(package, a["body"], f"the body of {artifact!r}")
    pay_p = _inside(package, a["payload"], f"the payload of {artifact!r}")
    payload = pay_p.read_bytes()
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
    # THE BYTES ARE ASKED AGAIN, NOT REMEMBERED. Between `before` and this run the package lay on a
    # machine, and a signature over a replaced payload verifies just as well as one over the checked
    # payload. So the digests the manifest promises and the derivation body -> payload are checked
    # here a second time, and nothing is assembled from a body that is not the checked one.
    for role, p, expected in (("payload", pay_p, a.get("payload_sha256")),
                              ("body", body_p, a.get("body_sha256"))):
        actual = _sha256(p) if p.is_file() else None
        if actual is None or actual != expected:
            print(f"VERDICT: the {role} {p.name} DIFFERS from the manifest "
                  f"({'missing' if actual is None else 'sha256 ' + actual[:16] + '...'}) -- it is not the "
                  f"{role} that was checked before signing. Nothing assembled.")
            return 1
    try:
        derived, why = _derived_payload(a, json.loads(body_p.read_text(encoding="utf-8")))
    except (ValueError, TypeError) as exc:
        print(f"VERDICT: the body does not have the form its kind prescribes ({exc}). Nothing assembled.")
        return 1
    if derived is None:
        print(f"VERDICT: NOT MEASURABLE -- the derivation body -> payload cannot be recomputed here ({why}). "
              "That is not a pass, and nothing is assembled.")
        return 2
    if derived != payload:
        print("VERDICT: the derivation DIFFERS: the payload is not what the body says, so the body "
              f"{body_p.name} is not what the signature covers. Nothing assembled.")
        return 1
    if verify is None:
        print(f"VERDICT: NOT MEASURABLE -- without proofbundle.signature the signature cannot be checked "
              f"here ({crypto_source}). That is not a pass.")
        return 2
    ok, why = verify(pub_b64, sig_b64, payload)
    print(f"VERDICT: the signature {'VERIFIES' if ok else 'DOES NOT VERIFY'} over exactly these bytes "
          f"with the anchor key {str(pub_b64)[:16]}...")
    if not ok:
        print(f"         {why}")
        return 1

    target = _inside(package, f"{artifact}.signed.json", f"the preview of {artifact!r}")
    body = json.loads(body_p.read_text(encoding="utf-8"))
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
