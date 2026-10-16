"""Mutation probe for the TRACE verifier: each guard, broken on purpose, must turn its tests red.

Every mutant below changes ONE guard of ``src/proofbundle/adapters/trace_record.py`` (or the type the
guard reads) and is applied to a throwaway copy of the tracked tree, never to the working tree. The
probe then runs ``tests/test_trace_record.py`` against the copy. A mutant counts as KILLED when the
run is red. Two mutants are declared EQUIVALENT, each with its reason. They must SURVIVE, and if one
of them is ever killed, its argument is stale and the probe fails.

Usage:  python interop/trace/mutation_probe.py     (exit 0: every mutant as declared)
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
TARGET = "src/proofbundle/adapters/trace_record.py"
TESTS = "tests/test_trace_record.py"

# (label, old text, new text, expect_killed)
MUTANTS = [
    ("embedded signature always valid", 'if _signature_valid("EdDSA", key, signature, message):', "if True:", True),
    ("JWS signature always valid", "if _signature_valid(alg, key, signature, signing_input):", "if True:", True),
    ("cnf binding always holds",
     "bound = cnf_thumb is not None and hmac.compare_digest(cnf_thumb, verified_key.thumbprint)", "bound = True", True),
    ("canonical payload never compared", "same = payload_bytes == canonical", "same = True", True),
    ("alg allow-list off", "    if alg not in _ALGS:\n", "    if False:\n", True),
    ("header member allow-list off", "    if others:\n", "    if False:\n", True),
    ("duplicate members accepted", "return loads_strict(text)", 'return __import__("json").loads(text)', True),
    ("safe-integer and finiteness walk off", 'why = _canonicalizable(rec, "")', "why = None", True),
    ("non-finite numbers pass the walk", "if not math.isfinite(cur):", "if False:", True),
    ("max age off by one", 'elif age > cfg["max_age"]:', 'elif age > cfg["max_age"] + 1:', True),
    ("future skew off by one", 'if age < -cfg["skew"]:', 'if age < -cfg["skew"] - 1:', True),
    ("nonce always matches",
     'same = type(actual) is str and hmac.compare_digest(actual.encode("utf-8"), cfg["nonce"].encode("utf-8"))',
     "same = True", True),
    ("policy hash always matches", 'same = type(actual) is str and actual in cfg["policy_hashes"]', "same = True", True),
    ("subject always in scope", 'same = type(actual) is str and actual in cfg["subjects"]', "same = True", True),
    ("transcript hash compared as str (raises on a non-ASCII record value)",
     'hmac.compare_digest(actual.encode("utf-8"),\n                                                               cfg["transcript_hash"].encode("ascii"))',
     'hmac.compare_digest(actual, cfg["transcript_hash"])', True),
    ("expected nonce not checked for a UTF-8 form", '            expected_nonce.encode("utf-8")\n',
     "            pass\n", True),
    ("transcript hash always matches",
     'same = type(actual) is str and hmac.compare_digest(actual.encode("utf-8"),\n'
     '                                                               cfg["transcript_hash"].encode("ascii"))',
     "same = True", True),
    ("unknown members permitted", "            f.extra(mp, False)", "            f.extra(mp, True)", True),
    ("profile check always passes", "if profile_value in accepted and type(profile_value) is str:", "if True:", True),
    ("weak Ed25519 trust anchor accepted", "        if weakness is not None:\n", "        if False:\n", True),
    ("EC trusted key not checked on the curve",
     "            ec.EllipticCurvePublicKey.from_encoded_point(curve, point)\n", "            pass\n", True),
    ("private trusted key accepted", "    if present:\n", "    if False:\n", True),
    ("integrity failure reported as exit 3",
     "    if any(name in _INTEGRITY for name in failed):\n        return 1", "    if False:\n        return 1", True),
    ("lenient base64url for the embedded signature", "signature = decode_b64url(sig_value)",
     'signature = __import__("base64").urlsafe_b64decode(sig_value + "==")', True),
    ("data_class not required", '"policy", "data_class",\n', '"policy",\n', True),
    ("URI format never checked", "if _string(v, p, f) and not _is_uri(v):", "if False:", True),
    ("origin rule of 3.1.1 off", 'and runtime.get("platform") != "software-only"):', "and False):", True),
    ("3.1.5 measurement equality off", 'and pm.get("measurement") != runtime.get("measurement")):', "and False):", True),
    # EQUIVALENT: one reference flipped alone. The other still blocks, so safeForAutomation stays false:
    # each reference alone keeps the automation verdict unsafe. The next mutant flips both.
    ("revocation alone claimed as checked", '"revocation_checked": False,', '"revocation_checked": True,', False),
    ("revocation and platform evidence claimed as checked",
     '"revocation_checked": False,\n        "platform_evidence_checked": False,',
     '"revocation_checked": True,\n        "platform_evidence_checked": True,', True),
    ("integers decided by spelling", "    return type(v) is float and math.isfinite(v) and v.is_integer()",
     "    return False", True),
    ("JWS payload may carry signature", '        if form == "jws-compact":\n            fs.bad(p,',
     '        if False:\n            fs.bad(p,', True),
    # EQUIVALENT: with the explicit refusal of 'none' gone, 'none' is still not in _ALGS and is refused
    # by the next line under the same check name, exit 2. Only the detail text changes.
    ("explicit alg none refusal removed", 'if type(alg) is str and alg.lower() == "none":', "if False:", False),
]


def tracked_copy(dest: Path) -> None:
    files = subprocess.run(["git", "-C", str(REPO), "ls-files", "-z"], capture_output=True, check=True).stdout
    for rel in files.decode().split("\0"):
        if not rel:
            continue
        src = REPO / rel
        if not src.is_file():
            continue
        out = dest / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, out)
    for rel in (TARGET, TESTS):  # the probe judges the working-tree state of these two files
        shutil.copy2(REPO / rel, dest / rel)


def run_tests(tree: Path) -> int:
    env = dict(os.environ, PYTHONPATH=str(tree / "src"), PYTHONDONTWRITEBYTECODE="1")
    return subprocess.run([sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", TESTS],
                          cwd=tree, env=env, capture_output=True, text=True).returncode


def main() -> int:
    ok = True
    with tempfile.TemporaryDirectory(prefix="trace-mutants-") as tmp:
        tree = Path(tmp) / "tree"
        tracked_copy(tree)
        target = tree / TARGET
        original = target.read_text(encoding="utf-8")
        probe = subprocess.run([sys.executable, "-c", "import proofbundle; print(proofbundle.__file__)"],
                               cwd=tree, env=dict(os.environ, PYTHONPATH=str(tree / "src")),
                               capture_output=True, text=True).stdout.strip()
        if not probe.startswith(str(tree)):
            print(f"the copy is not what gets imported: {probe}")
            return 2
        if run_tests(tree) != 0:
            print("baseline: the unmutated copy is red; no mutant can be judged")
            return 2
        print("baseline green")
        for label, old, new, expect_killed in MUTANTS:
            if original.count(old) != 1:
                print(f"STALE  {label}: the text to mutate occurs {original.count(old)} times")
                ok = False
                continue
            target.write_text(original.replace(old, new), encoding="utf-8")
            killed = run_tests(tree) != 0
            target.write_text(original, encoding="utf-8")
            verdict = "KILLED" if killed else "SURVIVED"
            as_declared = killed == expect_killed
            ok = ok and as_declared
            print(f"{'ok   ' if as_declared else 'GAP  '} {verdict:8s} {label}"
                  + ("" if expect_killed else "  (declared equivalent)"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
