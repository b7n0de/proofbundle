"""Build corpus.json: eval-result v0.1 envelopes as released versions emitted them, with the verdicts the
released 6.1.0 verifier gives on them. Not a test and not collected; it documents and repeats how the
fixture was made.

    python tests/fixtures/eval_result_v0_1/make_corpus.py --wheel <proofbundle-6.1.0-py3-none-any.whl>

Two origins, named per entry:

- ``fixture from release 6.1.0``: emitted by the published 6.1.0 wheel, unpacked, not installed. The
  wheel's SHA-256 is written into the corpus and checked here against the digest PyPI lists.
- ``own reconstruction from the source at tag vX.Y.Z``: emitted by the source tree at a release tag
  (``git archive``), because the published artifact of that version was not fetched. The tag commit is
  written into the corpus.

Every emitter runs in its own interpreter with only its own source on the path. Inputs are the ones of
``tests/test_intoto_examples.py``: the throwaway key (seed ``bytes(range(32))``), the salt ``0x11`` times
16, the root ``cmVjZWlwdC1tZXJrbGUtcm9vdA==``. No network.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
WHEEL_SHA256 = "f43164161952d78afa19bdbdc324a74f104103f417f8f7c7e8734cad72235b3b"
TAGS = ("v2.0.0", "v2.1.0", "v3.0.0", "v3.3.0", "v3.6.0", "v4.0.0", "v5.0.0", "v5.1.0", "v6.0.0")
VERDICT_KEYS = ("ok", "predicate_type", "predicate_type_ok", "content_root_alg", "content_root_ok",
                "content_root_detail")

CHILD = r'''
import base64, inspect, json, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import proofbundle
from proofbundle import intoto
from proofbundle.evalclaim import build_eval_claim, issuer_fingerprint
job = json.loads(sys.stdin.read())
keys = job["verdict_keys"]
signer = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
pub = signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
def verdict(res):
    return {k: res[k] for k in keys if k in res}
out = {"version": getattr(proofbundle, "__version__", None), "entries": [], "verdicts": []}
if job.get("emit"):
    claim, _ = build_eval_claim(
        suite="safety-refusals", suite_version="1.2.0", metric="refusal_rate", comparator=">=",
        threshold="0.98", score="0.994", n=500, model_id="acme/secret-model-7b",
        dataset_id="acme/internal-redteam-set", issuer=issuer_fingerprint(signer),
        timestamp="2026-07-05T12:00:00Z", model_salt=b"\x11" * 16, dataset_salt=b"\x11" * 16)
    params = inspect.signature(intoto.export_eval_result_dsse).parameters
    for v in job["emit"]:
        kw = dict(v["kwargs"])
        if "content_root_alg" in kw:
            if "content_root_alg" not in params:
                continue
            kw["content_root_alg"] = getattr(intoto, kw["content_root_alg"])
        c = dict(claim, **v.get("claim_extra", {}))
        env = intoto.export_eval_result_dsse(c, signer, **kw)
        out["entries"].append({"variant": v["name"], "envelope": env,
                               "own_verdict": verdict(intoto.verify_eval_result_dsse(env, pub))})
for item in job.get("verify", []):
    key = base64.b64decode(item["public_key_b64"])
    out["verdicts"].append(verdict(intoto.verify_eval_result_dsse(item["envelope"], key)))
print(json.dumps(out))
'''

RECEIPT = {"subject_profile": "receipt", "root_b64": "cmVjZWlwdC1tZXJrbGUtcm9vdA==",
           "harness": {"name": "inspect_ai", "version": "0.3.244"}}
WHEEL_VARIANTS = [
    {"name": "receipt, jcs-sha256-v1", "kwargs": dict(RECEIPT, content_root_alg="CONTENT_ROOT_ALG")},
    {"name": "receipt, legacy-sortkeys-json-v0",
     "kwargs": dict(RECEIPT, content_root_alg="LEGACY_CONTENT_ROOT_ALG")},
    {"name": "public-model", "kwargs": {"subject_profile": "public-model", "subject_name": "acme/open-model-7b",
                                        "subject_sha256": "a" * 64, "root_b64": RECEIPT["root_b64"]}},
    {"name": "release-gate", "kwargs": {"subject_profile": "release-gate",
                                        "subject_name": "acme/inference-service:1.4.2",
                                        "subject_sha256": "b" * 64, "root_b64": RECEIPT["root_b64"]}},
    {"name": "receipt with preRegistration and anchors",
     "kwargs": dict(RECEIPT, anchors=[{"kind": "example-anchor", "digest": {"sha256": "cc" * 32}}]),
     "claim_extra": {"prereg_sha256": "e5" * 32}},
]
TAG_VARIANTS = [{"name": "receipt, the version's default content root", "kwargs": dict(RECEIPT)}]


def run_child(src: Path, job: dict) -> dict:
    env = {"PYTHONPATH": str(src), "PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"}
    r = subprocess.run([sys.executable, "-c", CHILD], input=json.dumps(job), capture_output=True, text=True,
                       env=env, cwd=src, check=False)
    if r.returncode != 0:
        raise SystemExit(f"child at {src} failed:\n{r.stderr[-2000:]}")
    return json.loads(r.stdout)


def tag_source(tag: str, into: Path) -> tuple[Path, str]:
    commit = subprocess.run(["git", "rev-parse", f"{tag}^{{commit}}"], cwd=REPO, capture_output=True,
                            text=True, check=True).stdout.strip()
    archive = subprocess.run(["git", "archive", "--format=tar", tag, "src"], cwd=REPO, capture_output=True,
                             check=True).stdout
    dest = into / tag
    dest.mkdir()
    with tarfile.open(fileobj=__import__("io").BytesIO(archive)) as tar:
        tar.extractall(dest, filter="data")
    return dest / "src", commit


def negatives(envelope: dict) -> list:
    """Two envelopes the old verifier must refuse, for the same reason as the new one."""
    body = base64.b64decode(envelope["payload"])
    changed = body.replace(b'"passed":true', b'"passed":false', 1)
    assert changed != body
    kaputt = dict(envelope, payload=base64.b64encode(changed).decode())
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: PLC0415
    signer = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    statement = json.loads(body)
    loose = json.dumps(statement, indent=1).encode("utf-8")
    pae = b"DSSEv1 %d %s %d %s" % (len(envelope["payloadType"]), envelope["payloadType"].encode(), len(loose), loose)
    resigned = {"payload": base64.b64encode(loose).decode(), "payloadType": envelope["payloadType"],
                "signatures": [{"sig": base64.b64encode(signer.sign(pae)).decode()}]}
    return [{"case": "one payload byte changed, signature kept", "envelope": kaputt},
            {"case": "re-signed over bytes that are not canonical for the declared content root",
             "envelope": resigned}]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--wheel", type=Path, required=True)
    args = ap.parse_args()
    if hashlib.sha256(args.wheel.read_bytes()).hexdigest() != WHEEL_SHA256:
        raise SystemExit("the wheel is not the published 6.1.0 wheel")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: PLC0415
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: PLC0415
    own = Ed25519PrivateKey.from_private_bytes(bytes(range(32))).public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw)
    other = Ed25519PrivateKey.from_private_bytes(b"\x01" * 32).public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw)
    own_b64, other_b64 = base64.b64encode(own).decode(), base64.b64encode(other).decode()
    entries = []
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        wheel_dir = tmp_path / "wheel610"
        with zipfile.ZipFile(args.wheel) as z:
            z.extractall(wheel_dir)
        made = run_child(wheel_dir, {"verdict_keys": VERDICT_KEYS, "emit": WHEEL_VARIANTS})
        assert made["version"] == "6.1.0", made["version"]
        for e in made["entries"]:
            entries.append({"id": f"release-6.1.0-wheel/{e['variant']}",
                            "origin": f"fixture from release 6.1.0 (the published wheel, sha256 {WHEEL_SHA256})",
                            "origin_kind": "release-artifact", "version": "6.1.0", "variant": e["variant"],
                            "envelope": e["envelope"], "own_verdict": e["own_verdict"]})
        for tag in TAGS:
            src, commit = tag_source(tag, tmp_path)
            made = run_child(src, {"verdict_keys": VERDICT_KEYS, "emit": TAG_VARIANTS})
            for e in made["entries"]:
                entries.append({"id": f"reconstruction-{tag}/{e['variant']}",
                                "origin": f"own reconstruction from the source at tag {tag} (commit {commit})",
                                "origin_kind": "tag-reconstruction", "version": made["version"],
                                "variant": e["variant"], "envelope": e["envelope"], "own_verdict": e["own_verdict"]})
        for entry in entries:
            entry["negatives"] = []
            if entry["id"] in ("release-6.1.0-wheel/receipt, jcs-sha256-v1",
                               "release-6.1.0-wheel/receipt, legacy-sortkeys-json-v0",
                               "reconstruction-v2.0.0/receipt, the version's default content root"):
                entry["negatives"] = negatives(entry["envelope"])
        jobs = []
        for entry in entries:
            jobs.append({"envelope": entry["envelope"], "public_key_b64": own_b64})
            jobs.append({"envelope": entry["envelope"], "public_key_b64": other_b64})
            jobs += [{"envelope": n["envelope"], "public_key_b64": own_b64} for n in entry["negatives"]]
        verdicts = iter(run_child(wheel_dir, {"verdict_keys": VERDICT_KEYS, "verify": jobs})["verdicts"])
        for entry in entries:
            entry["release_6_1_0_verdict"] = next(verdicts)
            entry["release_6_1_0_verdict_other_key"] = next(verdicts)
            for n in entry["negatives"]:
                n["release_6_1_0_verdict"] = next(verdicts)
    corpus = {
        "about": ("eval-result v0.1 envelopes as released versions emitted them, and the verdicts the released "
                  "6.1.0 verifier gives on them. Made by make_corpus.py in this directory."),
        "public_key_b64": own_b64, "other_public_key_b64": other_b64, "verdict_keys": list(VERDICT_KEYS),
        "entries": entries,
    }
    (HERE / "corpus.json").write_text(json.dumps(corpus, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"{len(entries)} entries written")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
