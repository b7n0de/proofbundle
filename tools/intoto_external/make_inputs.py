#!/usr/bin/env python3
"""The inputs of the foreign-tool measurement: one eval receipt, exported by proofbundle's in-toto code.

WHAT IS EXPORTED. The export of 6.1.0 has three predicates, and the subject profile belongs to one of
them only:

  eval-result/v0.1   `proofbundle intoto`, once per subject profile: receipt, public-model, release-gate
  test-result/v0.1   `intoto.export_intoto_dsse`, library only; its subject is always the receipt binder
  svr/v0.1           `intoto.export_svr_dsse`, the function behind `proofbundle svr`; its subject is
                     always the receipt binder

So the matrix has five cells that exist and four that do not (test-result and svr under public-model
and release-gate). The four are recorded as not applicable, never built by hand: an attestation the
export cannot produce would measure something other than the export.

WHAT THE SUBJECTS ARE. receipt: the export's own binder over the receipt, whose preimage is written as
`receipt_binder.json` so a tool that verifies a blob can be given it. public-model: the sha256 of
`public_model.txt`, a stand-in for a disclosed model file. release-gate: the manifest digest of the OCI
image run.py builds on a local registry, passed in as --image-digest, so `cosign verify-attestation`
has an image whose digest is the subject.

CONTROLS, marked as such and never counted as the export: each of the five again in the legacy
content-root mode the export functions offer (`content_root_alg="legacy-sortkeys-json-v0"`), which
signs the same statement without the top-level `contentRootAlg` field; and the eval-result receipt
cell with a DSSE keyid, which the export can set and `proofbundle intoto` does not. A tool that reads
the control and refuses the export names the field, or the keyid, as the cause.

THE KEY is an Ed25519 test key whose seed is SHA-256 of the label below. It is printed here on
purpose: it signs test inputs only and trusts nothing. The salts and the SVR time are fixed the same
way, so a re-run on the same code writes the same bytes.

usage: make_inputs.py --image-digest sha256:<64 hex> --out DIR
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(REPO / "src"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from proofbundle import intoto  # noqa: E402
from proofbundle.intoto import LEGACY_CONTENT_ROOT_ALG  # noqa: E402
from proofbundle.bundle import recompute_merkle_root_b64  # noqa: E402
from proofbundle.evalclaim import build_eval_claim, decode_eval_claim, emit_eval_receipt  # noqa: E402

KEY_LABEL = b"proofbundle Z225 foreign-tool measurement test key, trusts nothing"
SEED = hashlib.sha256(KEY_LABEL).digest()
SVR_TIME = "2026-09-26T00:00:00Z"
PUBLIC_MODEL = b"z225 public model stand-in: the sha256 of this file is the public-model subject\n"
PROFILES = ("receipt", "public-model", "release-gate")


def _ssh_sha256_fingerprint(raw: bytes) -> str:
    """OpenSSH's SHA256 fingerprint of an Ed25519 key, the keyid go-securesystemslib's
    dsse.SHA256KeyID derives and sigstore's DSSE verifier compares with."""
    def string(b: bytes) -> bytes:
        return len(b).to_bytes(4, "big") + b
    digest = hashlib.sha256(string(b"ssh-ed25519") + string(raw)).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


#: the keyid of the keyid control
KEYID = _ssh_sha256_fingerprint(Ed25519PrivateKey.from_private_bytes(SEED).public_key().public_bytes_raw())


def _write_json(path: Path, obj) -> None:
    path.write_text(json.dumps(obj, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--image-digest", required=True, help="sha256:<hex> of the test image (release-gate)")
    ap.add_argument("--out", required=True, type=Path)
    a = ap.parse_args()
    algo, _, image_hex = a.image_digest.partition(":")
    if algo != "sha256" or len(image_hex) != 64:
        ap.error("--image-digest must be sha256:<64 hex>")
    out = a.out
    out.mkdir(parents=True, exist_ok=True)

    signer = Ed25519PrivateKey.from_private_bytes(SEED)
    pub_raw = signer.public_key().public_bytes_raw()
    (out / "test_key.pub.b64").write_text(base64.b64encode(pub_raw).decode() + "\n", encoding="ascii")
    (out / "public_model.txt").write_bytes(PUBLIC_MODEL)

    claim, _salts = build_eval_claim(
        suite="arc_easy", suite_version="1", metric="acc", comparator=">=", threshold="0.30",
        score="0.5567", n=2376, model_id="openai-community/gpt2", dataset_id="allenai/ai2_arc",
        issuer="", timestamp="2026-09-26T00:00:00Z", provenance={"harness": "lm-evaluation-harness"},
        model_salt=hashlib.sha256(b"z225 model salt").digest(),
        dataset_salt=hashlib.sha256(b"z225 dataset salt").digest())
    bundle = emit_eval_receipt(claim, signer)
    _write_json(out / "receipt.bundle.json", bundle)
    # what `proofbundle intoto` itself reads from the receipt
    signed_claim = decode_eval_claim(bundle)
    root_b64 = recompute_merkle_root_b64(bundle).get("stated_b64")

    # The receipt binder, byte for byte as intoto.resolve_subject hashes it.
    binder = json.dumps({"model_id_commit": signed_claim["model_id_commit"],
                         "dataset_id_commit": signed_claim.get("dataset_id_commit"),
                         "root_b64": root_b64, "timestamp": signed_claim["timestamp"]},
                        sort_keys=True, separators=(",", ":")).encode("utf-8")
    (out / "receipt_binder.json").write_bytes(binder)

    seed_file = out / ".seed.tmp"
    seed_file.write_bytes(SEED)
    subjects = {"receipt": (None, None),
                "public-model": ("public_model.txt", hashlib.sha256(PUBLIC_MODEL).hexdigest()),
                "release-gate": ("z225/img", image_hex)}
    made = {}
    try:
        for profile in PROFILES:
            name, sha = subjects[profile]
            target = out / f"eval-result.{profile}.dsse.json"
            cmd = [sys.executable, "-c", "import sys; from proofbundle.cli import main; sys.exit(main())",
                   "intoto", str(out / "receipt.bundle.json"),
                   "--key", str(seed_file), "--subject-profile", profile, "--out", str(target)]
            if name:
                cmd += ["--subject-name", name, "--subject-sha256", sha]
            r = subprocess.run(cmd, capture_output=True, text=True,
                               env={**os.environ, "PYTHONPATH": str(REPO / "src")})
            if r.returncode != 0:
                print(r.stdout + r.stderr, file=sys.stderr)
                return 1
            made[f"eval-result.{profile}"] = target.name
    finally:
        seed_file.unlink(missing_ok=True)

    _write_json(out / "test-result.receipt.dsse.json",
                intoto.export_intoto_dsse(signed_claim, signer, root_b64=root_b64))
    made["test-result.receipt"] = "test-result.receipt.dsse.json"
    _write_json(out / "svr.receipt.dsse.json", intoto.export_svr_dsse(bundle, signer, time_created=SVR_TIME))
    made["svr.receipt"] = "svr.receipt.dsse.json"

    controls = {}
    for profile in PROFILES:
        name, sha = subjects[profile]
        path = out / f"control.legacy.eval-result.{profile}.dsse.json"
        _write_json(path, intoto.export_eval_result_dsse(
            signed_claim, signer, subject_profile=profile, subject_name=name, subject_sha256=sha,
            root_b64=root_b64, content_root_alg=LEGACY_CONTENT_ROOT_ALG))
        controls[f"legacy.eval-result.{profile}"] = path.name
    _write_json(out / "control.legacy.test-result.receipt.dsse.json", intoto.export_intoto_dsse(
        signed_claim, signer, root_b64=root_b64, content_root_alg=LEGACY_CONTENT_ROOT_ALG))
    controls["legacy.test-result.receipt"] = "control.legacy.test-result.receipt.dsse.json"
    _write_json(out / "control.legacy.svr.receipt.dsse.json", intoto.export_svr_dsse(
        bundle, signer, time_created=SVR_TIME, content_root_alg=LEGACY_CONTENT_ROOT_ALG))
    controls["legacy.svr.receipt"] = "control.legacy.svr.receipt.dsse.json"
    _write_json(out / "control.keyid.eval-result.receipt.dsse.json", intoto.export_eval_result_dsse(
        signed_claim, signer, root_b64=root_b64, keyid=KEYID))
    controls["keyid.eval-result.receipt"] = "control.keyid.eval-result.receipt.dsse.json"

    _write_json(out / "inputs.json", {
        "made_by": "tools/intoto_external/make_inputs.py",
        "public_key_b64": base64.b64encode(pub_raw).decode(),
        "subjects": {"receipt": hashlib.sha256(binder).hexdigest(),
                     "public-model": subjects["public-model"][1],
                     "release-gate": image_hex},
        "keyid_of_the_keyid_control": KEYID,
        "attestations": made,
        "controls": controls,
        "not_applicable": {
            "test-result.public-model": "export_intoto_dsse takes no subject profile; its subject is the receipt binder",
            "test-result.release-gate": "export_intoto_dsse takes no subject profile; its subject is the receipt binder",
            "svr.public-model": "export_svr_dsse takes no subject profile; its subject is the receipt binder",
            "svr.release-gate": "export_svr_dsse takes no subject profile; its subject is the receipt binder",
        },
    })
    print(json.dumps(made, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
