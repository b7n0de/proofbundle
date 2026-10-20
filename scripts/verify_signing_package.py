#!/usr/bin/env python3
"""Verify a signing package OFFLINE, before and after the signature is made.

WHAT THIS IS FOR. A release that signs artefacts produces, for each of them, two files: the BODY
(``<name>.body.json``, readable JSON) and the CANONICAL BYTES (``<name>.payload.bin``, exactly what
the signature runs over). The second file is what gets signed. This tool answers the two questions
that have to be asked around that act:

  before  Does what I am about to sign match what I can read? And does it bind the candidate I mean
          to release -- commit, tree digest, distribution digests? It prints the digest of the
          manifest it reviewed.
  after   Does my signature verify over exactly those bytes, with exactly my key, and are they the
          bytes of the manifest `before` reviewed?

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
         "binds_candidate": true | false}        # default true; a receipt binds none (see below)
      ]
    }

The candidate's commit is a git object id of 40 or 64 hex digits and its three digests have 64. Every
field of a body has to be covered by the signed form of its kind: a statement signs the whole body, a
receipt only its nine fields, so a receipt carries no candidate block and says binds_candidate false.
A receipt binds its tree through its signed subject_tree_digest; this tool does not compare that value
with the manifest's candidate, so a receipt's tree is not checked against the candidate here.

`after` judges the whole package again with every check `before` makes, against the head it is given,
and writes its preview as a new file that never lands on an input of the run.

Usage:
    python3 scripts/verify_signing_package.py before --package <dir> [--expected-head <sha>]
    python3 scripts/verify_signing_package.py after  --package <dir> --artifact <name> --signature <file>
                                                     --reviewed-manifest-sha256 <digest before printed>

Every JSON file of the package is read once and with the package's strict reader, so a name given twice
is a finding and not a second reading of the same file.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import sys
import tempfile

DEFAULT_MANIFEST = "MANIFEST.json"
#: A file the producer leaves behind while a step is still running. Its presence means the package
#: is incomplete, and an incomplete package must never be signed.
IN_PROGRESS_MARKER = ".step_running"

#: The four fields a candidate binding names. A binding that leaves one out does not bind it. The first
#: version compared only the fields the manifest happened to carry, so an empty `candidate` compared
#: nothing and still printed a match (Codex on pull request 369, round one, P1).
CANDIDATE_FIELDS = ("commit", "tree_digest", "sdist_sha256", "wheel_sha256")
#: What each candidate field has to look like to name an object at all.
_CANDIDATE_FORM = {"commit": re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?"),
                   "tree_digest": re.compile(r"[0-9a-f]{64}"), "sdist_sha256": re.compile(r"[0-9a-f]{64}"),
                   "wheel_sha256": re.compile(r"[0-9a-f]{64}")}
_CANDIDATE_FORM_TEXT = {"commit": "a git object id of 40 or 64 lower-case hex digits",
                        "tree_digest": "64 lower-case hex digits", "sdist_sha256": "64 lower-case hex digits",
                        "wheel_sha256": "64 lower-case hex digits"}
#: The two kinds of artefact, each with its own signed form.
ARTIFACT_KINDS = ("receipt", "statement")

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


def _strict_reader():
    """(function, source) or (None, reason): the package's one strict JSON parser.

    A NAME GIVEN TWICE IS A FINDING. `json.loads` keeps the LAST of two members of one name, and another
    reader may keep the first. A body with two `candidate` members, the second one matching the
    manifest, passed `before` with exit 0 while a first-wins reader saw other distribution digests
    (Codex on pull request 369, round two, P1). `loads_strict` refuses a name given twice at any depth,
    a lone surrogate and an implausible integer, and every JSON file of the package goes through it,
    the manifest included."""
    try:
        from proofbundle._strict_json import loads_strict  # noqa: PLC0415
        from proofbundle.errors import ProofBundleError  # noqa: PLC0415
    except ImportError as exc:
        return None, f"proofbundle._strict_json not importable ({exc})"

    def read(text: str):
        try:
            return loads_strict(text)
        except ProofBundleError as exc:
            raise ValueError(str(exc)) from None
    return read, "proofbundle._strict_json.loads_strict"


class _NotStrictJson(ValueError):
    """A file of the package that is not strict JSON: a finding about the package."""


def _strict_json(raw: bytes, what: str):
    """The value in `raw`, parsed once and strictly from bytes read once. Raises _NotStrictJson for bytes
    that are not strict UTF-8 JSON, a name given twice included, and ImportError when the strict reader
    is missing here, which the callers report as NOT MEASURABLE."""
    reader, source = _strict_reader()
    if reader is None:
        raise ImportError(source)
    try:
        return reader(raw.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise _NotStrictJson(f"{what} is not UTF-8 ({exc})") from None
    except ValueError as exc:
        raise _NotStrictJson(f"{what}: {exc}") from None


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
    if a["kind"] == "receipt":
        fn, source = _receipt_payload()
        return (fn(body), source) if fn is not None else (None, source)
    fn, source = _canonicalizer()
    if fn is None:
        return None, source
    return fn({k: v for k, v in body.items() if k != "signature"}), source


def _judge_artefact(a: dict, body_p: pathlib.Path, pay_p: pathlib.Path, raw: dict, cand: dict,
                    expected_head: str | None) -> dict:
    """Every check one artefact gets, over bytes the caller read once (`raw`: role -> bytes, a missing
    role absent): {"lines", "findings", "not_measurable", "body", "derived"}.

    ONE JUDGEMENT FOR BOTH PHASES (Codex on pull request 369, round three). The digest `after` is bound
    to says which manifest `before` read, not that `before` accepted it, and anyone can compute it. A
    body whose candidate differed from the manifest made `before` exit 1 and still print the digest, and
    `after` then assembled that body with exit 0. `after` now runs these same checks on the artefact it
    assembles, so a finding of `before` is a finding of `after`.

    EVERY FIELD OF THE BODY IS ONE THE SIGNATURE COVERS (the same round, P1). A receipt is signed in its
    compact nine-field form, which carries no `candidate`, so `before` reported a candidate as bound
    that the signature did not cover, and the preview carried it beside a valid signature. The fields
    the signed form covers are read from the derived payload itself, never from a copied list, and a
    body field outside them is a finding; a receipt therefore binds no candidate here. Its tree is bound
    by its signed `subject_tree_digest`, which this tool does not compare with the manifest's candidate.
    """
    lines: list = []
    findings = not_measurable = 0
    for role, p, expected in (("body", body_p, a.get("body_sha256")),
                              ("payload", pay_p, a.get("payload_sha256"))):
        data = raw.get(role)
        if data is None:
            lines.append(f"   {role:<8} MISSING: {p.name}")
            findings += 1
            continue
        actual = hashlib.sha256(data).hexdigest()
        ok = actual == expected
        lines.append(f"   {role:<8} {p.name}  {len(data)} B  sha256 {actual[:16]}...  "
                     f"{'matches the manifest' if ok else 'DIFFERS from the manifest'}")
        if not ok:
            findings += 1

    body, body_unreadable = None, None
    if raw.get("body") is not None:
        try:
            body = _strict_json(raw["body"], body_p.name)
        except _NotStrictJson as exc:
            body_unreadable = str(exc)
            lines.append(f"   body     not strict JSON ({exc}). Do not sign.")
            findings += 1
        except ImportError as exc:
            body_unreadable = str(exc)
            lines.append(f"   body     NOT MEASURABLE, it cannot be read strictly here ({exc})")
            not_measurable += 1
        else:
            if not isinstance(body, dict):
                body_unreadable = "the body is not a JSON object"
                lines.append("   body     is not a JSON object. Do not sign.")
                findings += 1
                body = None

    if body is not None:
        binds = a.get("binds_candidate", True)
        if binds and a["kind"] == "receipt":
            lines.append("   candidate: a receipt's signed form carries no `candidate`, so a receipt binds none -- "
                         "the manifest must say binds_candidate false for it")
            findings += 1
        elif binds:
            c = body.get("candidate")
            if c is not None and not isinstance(c, dict):
                lines.append(f"   candidate is a {type(c).__name__} in the body, not an object -- a binding of "
                             "that shape binds nothing")
                findings += 1
                c = None
            c = c or {}
            # EVERY FIELD, NOT THE ONES THAT HAPPEN TO BE THERE. A field the manifest leaves out is a field
            # nobody binds, and a comparison over no fields is no comparison.
            missing = [f for f in CANDIDATE_FIELDS if not cand.get(f)]
            differ = [f for f in CANDIDATE_FIELDS if cand.get(f) and c.get(f) != cand.get(f)]
            if missing:
                lines.append(f"   candidate INCOMPLETE: the manifest names no {', '.join(missing)} -- a binding "
                             "that leaves a field out does not bind it")
                findings += 1
            if differ:
                lines.append("   candidate DIFFERS from the package head")
                findings += 1
                for f in differ:
                    lines.append(f"            {f}: body {str(c.get(f))[:16]}... vs head {str(cand.get(f))[:16]}...")
            if not missing and not differ:
                lines.append("   candidate matches the package head")
            if expected_head and c.get("commit") != expected_head:
                lines.append(f"            candidate.commit {str(c.get('commit'))[:16]}... is NOT the expected head "
                             f"{expected_head[:16]}... -- DIFFERS")
                findings += 1
        else:
            # THE OTHER DIRECTION IS THE HARD ONE. An artefact the manifest says does NOT bind a candidate
            # must not carry half a candidate block either: that would be a binding nobody checks, which is
            # the exact shape this tool exists to refuse.
            lines.append("   candidate: the manifest says this artefact binds no candidate")
            if body.get("candidate"):
                lines.append("            BUT it carries a candidate block -- a binding nobody checks does not "
                             "belong in an artefact.")
                findings += 1
            if not body.get("version"):
                lines.append("            AND it carries no version field -- then it binds nothing at all.")
                findings += 1
        for key in ("signature", "signer_pubkey"):
            if key in body:
                lines.append(f"            the body already carries {key} -- nothing may be signed over that.")
                findings += 1

    derived, why, broken = None, "a file is missing", None
    if body is not None and raw.get("payload") is not None:
        try:
            derived, why = _derived_payload(a, body)
        except (ValueError, TypeError) as exc:
            broken = exc
    if body_unreadable is not None:
        lines.append("   derivation not made, the body above could not be read")
    elif broken is not None:
        lines.append(f"   derivation IMPOSSIBLE: the body does not have the form its kind prescribes ({broken}). "
                     "Do not sign.")
        findings += 1
    elif derived is None:
        lines.append(f"   derivation NOT MEASURABLE ({why}) -- the digests above were checked, the equality "
                     "body -> payload was NOT.")
        not_measurable += 1
    else:
        stored = raw["payload"]
        if derived == stored:
            lines.append(f"   derivation body -> payload BYTE IDENTICAL ({len(stored)} B) -- what you read is "
                         "what you sign.")
        else:
            lines.append(f"   derivation DIFFERS: {len(derived)} B from the body, {len(stored)} B in the payload. "
                         "Do not sign.")
            findings += 1
        covered = json.loads(derived)
        outside = sorted(k for k in body if k not in covered and k not in ("signature", "signer_pubkey"))
        if outside:
            lines.append(f"   fields the signature does not cover: {', '.join(outside)} -- a value outside the "
                         "signed form can be changed after signing. Do not sign.")
            findings += 1
    return {"lines": lines, "findings": findings, "not_measurable": not_measurable, "body": body,
            "derived": derived}


def _judge_package(package: pathlib.Path, m: dict, cand: dict, expected_head: str | None):
    """Every artefact of the package judged with `_judge_artefact`, over bytes read once: (per artefact a
    tuple (a, body path, payload path, bytes by role, judgement), findings, not measurable).

    EACH FILE IS READ ONCE, and the digest, the parse and the derivation all take those bytes. A second
    read is a second file as far as the checks are concerned. The bytes are kept by resolved path, so two
    entries that name the same file judge the same bytes.

    ONE JUDGEMENT OF THE WHOLE PACKAGE FOR BOTH PHASES (Codex on pull request 369, round three, and the
    reading of its fix). `after` judged only the artefact it assembled and knew no expected head, so a
    finding of `before` in another artefact or against the head did not stop it. Both phases now judge
    every artefact here, with the head the caller gives."""
    gelesen: dict = {}
    alle, findings, not_measurable = [], 0, 0
    for a in m["artifacts"]:
        body_p = package / a["body"]
        pay_p = package / a["payload"]
        raw: dict = {}
        for role, datei in (("body", body_p), ("payload", pay_p)):
            if datei.is_file():
                ort = str(datei.resolve())
                if ort not in gelesen:
                    gelesen[ort] = datei.read_bytes()
                raw[role] = gelesen[ort]
        urteil = _judge_artefact(a, body_p, pay_p, raw, cand, expected_head)
        alle.append((a, body_p, pay_p, raw, urteil))
        findings += urteil["findings"]
        not_measurable += urteil["not_measurable"]
    return alle, findings, not_measurable


def load_manifest(package: pathlib.Path, name: str = DEFAULT_MANIFEST) -> dict:
    """The manifest, or a stated reason to stop (see `load_manifest_and_digest`)."""
    return load_manifest_and_digest(package, name)[0]


def load_manifest_and_digest(package: pathlib.Path, name: str = DEFAULT_MANIFEST) -> "tuple[dict, str]":
    """The manifest and the sha256 of the bytes it was parsed from, or a stated reason to stop. Every
    failure here is a finding, not a traceback: a broken package is a result, and the reader needs the
    result, not a stack. The file is read once; the digest `before` prints and `after` is bound to is
    taken over exactly the bytes that were judged."""
    marker = package / IN_PROGRESS_MARKER
    if marker.exists():
        raise SystemExit(f"STOP: {marker.name} is present ({marker.read_text(encoding='utf-8').strip()}): "
                         "a producing step did not finish, so the package is incomplete. Do not sign.")
    p = package / name
    if not p.is_file():
        raise SystemExit(f"STOP: {p.name} is missing -- without a manifest it is not known what belongs "
                         "to the package, and 'whatever lies here' is not a set.")
    raw = p.read_bytes()
    try:
        m = _strict_json(raw, p.name)
    except _NotStrictJson as exc:
        raise SystemExit(f"STOP: {p.name} is not readable JSON ({exc}) -- the package is damaged. Do not sign.")
    except ImportError as exc:
        print(f"VERDICT: NOT MEASURABLE -- {p.name} cannot be read strictly here ({exc}). That is not a pass: "
              "install proofbundle and run again.")
        raise SystemExit(2) from None
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
    # leave the next reader to remember it. A name given to two artefacts names neither: `after` took the
    # first of them (the reading of round three).
    namen = [a.get("name") if isinstance(a, dict) else None for a in m["artifacts"]]
    doppelt = sorted({n for n in namen if isinstance(n, str) and namen.count(n) > 1})
    if doppelt:
        raise SystemExit(f"STOP: {p.name} gives the artefact name {doppelt[0]!r} more than once. Do not sign.")
    for a in m["artifacts"]:
        if not isinstance(a, dict):
            raise SystemExit(f"STOP: {p.name} lists an artefact that is not an object ({a!r}). Do not sign.")
        name = a.get("name")
        if not isinstance(name, str) or not _ARTIFACT_NAME.match(name):
            raise SystemExit(f"STOP: the artefact name {name!r} is not a plain name -- it becomes part of a "
                             "file name inside the package and may not be a path. Do not sign.")
        for role in ("body", "payload"):
            _inside(package, a.get(role), f"the {role} of {name!r}")
        # A DISCRIMINATOR IS ONE OF ITS VALUES, NOT A TRUTH VALUE (Codex on pull request 369, rounds two
        # and three). A misspelled `kind` was taken as a statement and `binds_candidate: "no"` as a
        # binding; both decide which checks and which signed form apply.
        if a.get("kind") not in ARTIFACT_KINDS:
            raise SystemExit(f"STOP: the artefact {name!r} names the kind {a.get('kind')!r}; a kind is one of "
                             f"{', '.join(ARTIFACT_KINDS)}. Do not sign.")
        if "binds_candidate" in a and not isinstance(a["binds_candidate"], bool):
            raise SystemExit(f"STOP: binds_candidate of {name!r} is {a['binds_candidate']!r}, not true or false. "
                             "Do not sign.")
    # A MEMBER OF THE WRONG SHAPE IS A FINDING, NOT A TRACEBACK. `anchor` as a string or `candidate` as a
    # list reached `.get` on a value that has none (the reading of round two, a neighbour of the class the
    # strict reader closes). Absent or null stays absent.
    for key in ("anchor", "candidate"):
        if m.get(key) is not None and not isinstance(m[key], dict):
            raise SystemExit(f"STOP: {p.name} carries `{key}` as {type(m[key]).__name__}, not as an object. "
                             "Do not sign.")
    # A CANDIDATE FIELD THAT CANNOT NAME ITS OBJECT BINDS NOTHING (Codex on pull request 369, round
    # three). The check compared truth values, so `tree_digest: "x"` and a list as `wheel_sha256`, copied
    # into the body, printed a match. A commit is a 40 or 64 digit object id, a digest 64 hex digits.
    for field, value in (m.get("candidate") or {}).items():
        form = _CANDIDATE_FORM.get(field)
        if form is not None and not (isinstance(value, str) and form.fullmatch(value)):
            raise SystemExit(f"STOP: candidate.{field} is {value!r}, which is no {field} -- it must be "
                             f"{_CANDIDATE_FORM_TEXT[field]}. Do not sign.")
    # THE PREVIEW NEVER LANDS ON AN INPUT (Codex on pull request 369, round three). An artefact whose body
    # was `art.signed.json` passed every check, and the preview then overwrote the body it had just
    # checked; the same held for a payload, another artefact's file and the manifest.
    eingaben = {p.resolve(): p.name}
    for a in m["artifacts"]:
        for role in ("body", "payload"):
            eingaben.setdefault((package / a[role]).resolve(), f"the {role} of {a['name']!r}")
    for a in m["artifacts"]:
        ziel = (package / f"{a['name']}.signed.json").resolve()
        if ziel in eingaben:
            raise SystemExit(f"STOP: the preview of {a['name']!r} would be written over {eingaben[ziel]}. "
                             "Do not sign.")
    return m, hashlib.sha256(raw).hexdigest()


def before(package: pathlib.Path, manifest_name: str = DEFAULT_MANIFEST,
           expected_head: str | None = None, anchor_pubkey: str | None = None) -> int:
    m, manifest_digest = load_manifest_and_digest(package, manifest_name)
    _, canon_source = _canonicalizer()
    _, receipt_source = _receipt_payload()
    findings = 0
    not_measurable = 0

    print("# Offline verification of a signing package, BEFORE the signature")
    print(f"# package       : {package}")
    print(f"# manifest      : sha256 {manifest_digest}")
    print("#                 the manifest this run reviewed; pass it to `after` as --reviewed-manifest-sha256")
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

    alle, f_paket, n_paket = _judge_package(package, m, cand, expected_head)
    for a, _body_p, _pay_p, _raw, urteil in alle:
        print(f"## {a['name']}")
        if a.get("target_rel"):
            print(f"   target in repo: {a['target_rel']}")
        for zeile in urteil["lines"]:
            print(zeile)
        print()
    findings += f_paket
    not_measurable += n_paket

    if findings:
        print(f"VERDICT: {findings} finding(s) -- do not sign until they are resolved")
        return 1
    if not_measurable:
        print(f"VERDICT: NOT MEASURABLE -- {not_measurable} check(s) could not be made here: the equality")
        print("         body -> payload (no canonicalizer, or a file is missing), the strict reading of a")
        print("         body (no proofbundle._strict_json) or the anchor rule (no proofbundle.signature).")
        print("         That is not a pass: install proofbundle with rfc8785 and cryptography, run")
        print("         'before' again, and only then sign.")
        return 2
    print("VERDICT: everything checked and consistent")
    return 0


def after(package: pathlib.Path, artifact: str, signature_file: pathlib.Path,
          manifest_name: str = DEFAULT_MANIFEST, anchor_pubkey: str | None = None,
          reviewed_manifest_sha256: str | None = None, expected_head: str | None = None) -> int:
    m, manifest_digest = load_manifest_and_digest(package, manifest_name)
    a = next((x for x in m["artifacts"] if x["name"] == artifact), None)
    if a is None:
        raise SystemExit(f"STOP: {artifact!r} is not in the manifest. Present: "
                         f"{[x['name'] for x in m['artifacts']]}")
    verify, crypto_source = _ed25519_verifier()
    sig_b64 = signature_file.read_text(encoding="utf-8").strip()
    pub_b64 = (m.get("anchor") or {}).get("public_key_b64")

    print("# Offline verification, AFTER the signature")
    print(f"# artefact : {artifact}")
    print(f"# manifest : sha256 {manifest_digest}")
    print(f"# verifier : {crypto_source}")
    if anchor_pubkey is None:
        # SELF-ATTESTATION, SAID OUT LOUD. Without a key from outside this package, the check is
        # "the signature matches the key the package itself names" -- which any producer of the
        # package can satisfy, including one who swapped both. The `before` path already said this;
        # leaving it unsaid here was an inconsistency a foreign-family review pointed at.
        print("# anchor   : NOT checked against an independent source. This run only shows that the")
        print("#            signature matches the key THE PACKAGE NAMES. Pass --anchor-pubkey to")
        print("#            check it against a key you know from somewhere else.")
    if expected_head is None:
        print("# expected head : NOT checked. Pass --expected-head to compare the candidate with a head you know.")
    if anchor_pubkey is not None and pub_b64 != anchor_pubkey:
        print(f"VERDICT: the manifest's anchor key {str(pub_b64)[:16]}... is NOT the key you passed -- "
              "the signature was not checked against your key.")
        return 1
    # BOUND TO THE MANIFEST `before` REVIEWED. The digests below come from the manifest that lies in the
    # package now, so a manifest replaced together with its body and payload, digests updated and the new
    # payload signed, verified against itself (Codex on pull request 369, round two, P1). The digest
    # `before` printed names the manifest the human looked at; another one is a finding.
    if reviewed_manifest_sha256 is not None and reviewed_manifest_sha256 != manifest_digest:
        print(f"VERDICT: this is not the manifest `before` reviewed: sha256 {manifest_digest[:16]}... here, "
              f"{reviewed_manifest_sha256[:16]}... reviewed. Its files may be consistent with it and still "
              "not be the ones that were checked. Nothing assembled.")
        return 1
    # THE BYTES ARE ASKED AGAIN, NOT REMEMBERED, AND THE WHOLE PACKAGE IS JUDGED AGAIN. The digest above
    # says which manifest was read, not that `before` accepted it, and the package lay on a machine since.
    # So every check `before` makes, on every artefact and against the head given here, runs again over
    # bytes read once, and nothing is assembled from a package `before` would refuse.
    alle, findings, not_measurable = _judge_package(package, m, m.get("candidate") or {}, expected_head)
    for x, _body_p, _pay_p, _raw, urteil in alle:
        print(f"## {x['name']}")
        for zeile in urteil["lines"]:
            print(zeile)
    if findings:
        print(f"VERDICT: {findings} finding(s) in the package, the checks `before` makes fail here too, so it is "
              "not what should have been signed. Nothing assembled.")
        return 1
    _x, _body_p, pay_p, raw, urteil = next(e for e in alle if e[0] is a)
    if not_measurable or urteil["derived"] is None:
        print("VERDICT: NOT MEASURABLE -- a check of the package could not be made here (see above). That is "
              "not a pass, and nothing is assembled.")
        return 2
    payload, body = raw["payload"], urteil["body"]
    print(f"# payload  : {a['payload']}  {len(payload)} B  sha256 {hashlib.sha256(payload).hexdigest()}")
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
    if reviewed_manifest_sha256 is None:
        print("VERDICT: NOT MEASURABLE -- this run is not bound to the manifest `before` reviewed, so it cannot "
              "say that the bytes signed are the bytes that were checked. Pass the digest `before` printed as "
              "--reviewed-manifest-sha256. That is not a pass, and nothing is assembled.")
        return 2

    target = _inside(package, f"{artifact}.signed.json", f"the preview of {artifact!r}")
    # A PREVIEW NEVER WRITES INTO A FILE THAT IS ALREADY THERE (the readings of rounds two and three, and
    # Codex on pull request 369, round three). A link there wrote the preview into whatever it named, and a
    # second hard name of an input, the signed payload or the manifest, had that input overwritten after
    # exit 0; `load_manifest_and_digest` refuses only a path that resolves to an input. So a link is
    # refused, so is any path that is the same file as an input or as the signature file, and the preview is
    # written as a new file that replaces the name, never into an existing one.
    if target.is_symlink():
        print(f"VERDICT: the preview path {target.name} is a symbolic link, and a preview is never written "
              "through one. Nothing assembled.")
        return 1
    if target.exists():
        eingaben = [package / manifest_name, signature_file]
        eingaben += [package / e[r] for e in m["artifacts"] for r in ("body", "payload")]
        gleich = [str(e) for e in eingaben if e.exists() and os.path.samefile(target, e)]
        if gleich:
            print(f"VERDICT: the preview path {target.name} is the same file as {gleich[0]}, an input of this "
                  "run. Nothing assembled.")
            return 1
    # The preview is the body that was checked, parsed once above, not a fresh read of the file.
    body = dict(body)
    if a.get("kind") == "receipt":
        # A receipt carries the signature as a STRING plus signer_pubkey; a statement carries the
        # structured block. Writing the wrong one produces a file that the gate rejects, and the
        # rejection would look like a bad signature rather than a bad assembly.
        body["signature"] = sig_b64
        body["signer_pubkey"] = pub_b64
    else:
        body["signature"] = {"alg": "ed25519", "public_key_b64": pub_b64, "sig_b64": sig_b64}
    text = (json.dumps(body, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    fd, neu_pfad = tempfile.mkstemp(prefix=f".{target.name}.", dir=str(target.parent))
    with os.fdopen(fd, "wb") as fh:
        fh.write(text)
    os.replace(neu_pfad, target)
    print(f"         PREVIEW assembled -> {target.name} ({len(text)} B, sha256 "
          f"{hashlib.sha256(text).hexdigest()[:16]}...). This is a preview, not the artefact for the repository: the")
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
    for q in (b, a):
        q.add_argument("--expected-head", default=None,
                       help="the candidate head (40 hex) from an INDEPENDENT source, e.g. git ls-remote")
    a.add_argument("--artifact", required=True)
    a.add_argument("--signature", required=True, type=pathlib.Path)
    a.add_argument("--reviewed-manifest-sha256", default=None, type=_manifest_digest,
                   help="the manifest digest `before` printed; without it `after` assembles nothing and "
                        "answers NOT MEASURABLE")
    ns = p.parse_args(argv)
    if ns.mode == "before":
        return before(ns.package, ns.manifest, ns.expected_head, ns.anchor_pubkey)
    return after(ns.package, ns.artifact, ns.signature, ns.manifest, ns.anchor_pubkey,
                 ns.reviewed_manifest_sha256, ns.expected_head)


def _manifest_digest(text: str) -> str:
    """The digest exactly as `before` prints it; any other spelling is refused, not normalised."""
    if not re.fullmatch(r"[0-9a-f]{64}", text):
        raise argparse.ArgumentTypeError("the manifest digest `before` printed: 64 lower-case hex digits")
    return text


if __name__ == "__main__":
    sys.exit(main())
