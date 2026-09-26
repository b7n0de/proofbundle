#!/usr/bin/env python3
"""Z225: proofbundle's in-toto export, read and checked by foreign tools. Writes results/.

Runs with proofbundle's own Python (it calls make_inputs.py); every foreign tool is a separate
binary or environment given on the command line, so none of them imports proofbundle:

  --go-probe   the binary built from go/ (in-toto attestation Go binding, go-securesystemslib DSSE)
  --py         a Python with in-toto-attestation and securesystemslib[crypto] (probe_python.py)
  --bin        a directory with cosign, crane, registry (go-containerregistry), guacone and guacgql

Steps: a local OCI registry and a two-file test image built from bytes in this script; the inputs
(make_inputs.py, with the image digest as the release-gate subject); then per attestation and per
control: both probes, `cosign verify-attestation` against the image, `cosign verify-blob-attestation`
against the subject's own bytes, and a GUAC ingestion into an in-memory graph, followed by a query of
what the graph holds. A GUAC control that GUAC must ingest (a SLSA provenance statement over the
same image under the same key) runs first; if it fails, the GUAC rows say NOT MEASURABLE.

Everything runs on localhost. cosign runs with --insecure-ignore-tlog, since no transparency log is
part of this measurement, and its HOME is a scratch directory.

usage: run.py --go-probe PATH --py PATH --bin DIR [--out DIR]
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import os
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import make_inputs as MI  # noqa: E402
from proofbundle._wire_b64 import decode_b64  # noqa: E402

IMAGE_FILES = {"artifact.txt": b"z225 release artifact stand-in\n",
               "README": b"test image of tools/intoto_external/run.py; it carries nothing\n"}
SLSA_V1 = "https://slsa.dev/provenance/v1"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _run(cmd, **kw) -> subprocess.CompletedProcess:
    return subprocess.run([str(c) for c in cmd], capture_output=True, text=True, timeout=600, **kw)


def _last_error(text: str) -> str:
    lines = [ln for ln in text.splitlines() if ln.strip() and not ln.startswith("WARNING")]
    return lines[-1][:400] if lines else ""


def _wait(url: str, seconds: float = 30) -> None:
    end = time.time() + seconds
    while time.time() < end:
        try:
            urllib.request.urlopen(url, timeout=2)
            return
        except urllib.error.HTTPError:  # an HTTP answer of any status: the server is up
            return
        except Exception:  # noqa: BLE001 - not up yet
            time.sleep(0.3)
    raise RuntimeError(f"{url} did not come up")


def _layer_tar() -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        for name in sorted(IMAGE_FILES):
            info = tarfile.TarInfo(name)
            info.size, info.mtime, info.mode = len(IMAGE_FILES[name]), 1767225600, 0o644
            tf.addfile(info, io.BytesIO(IMAGE_FILES[name]))
    return buf.getvalue()


def _gql(port: int, query: str) -> dict:
    req = urllib.request.Request(f"http://127.0.0.1:{port}/query", data=json.dumps({"query": query}).encode(),
                                 headers={"content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


GRAPH_QUERY = """{ artifacts(artifactSpec: {}) { algorithm digest }
  HasSLSA(hasSLSASpec: {}) { id }
  HasMetadata(hasMetadataSpec: {}) { id }
  CertifyGood(certifyGoodSpec: {}) { id }
  IsOccurrence(isOccurrenceSpec: {}) { id } }"""


def _graph(port: int) -> dict:
    d = _gql(port, GRAPH_QUERY).get("data") or {}
    return {"artifacts": sorted(f"{a['algorithm']}:{a['digest']}" for a in d.get("artifacts") or []),
            "HasSLSA": len(d.get("HasSLSA") or []), "HasMetadata": len(d.get("HasMetadata") or []),
            "CertifyGood": len(d.get("CertifyGood") or []), "IsOccurrence": len(d.get("IsOccurrence") or [])}


def _slsa_control(image_hex: str) -> dict:
    """A SLSA provenance v1 statement over the test image, signed with the test key and the keyid
    GUAC's verifier looks up: the GUAC control. Built here, not by proofbundle."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: PLC0415
    st = {"_type": "https://in-toto.io/Statement/v1",
          "subject": [{"name": "z225/img", "digest": {"sha256": image_hex}}],
          "predicateType": SLSA_V1,
          "predicate": {"buildDefinition": {"buildType": "https://example.invalid/z225/control/v1",
                                            "externalParameters": {},
                                            "resolvedDependencies": [{
                                                "uri": "https://example.invalid/z225/source",
                                                "digest": {"sha256": hashlib.sha256(b"z225 source").hexdigest()}}]},
                        "runDetails": {"builder": {"id": "https://example.invalid/z225/control-builder"},
                                       "metadata": {"invocationId": "z225-control",
                                                    "startedOn": "2026-09-26T00:00:00Z",
                                                    "finishedOn": "2026-09-26T00:00:00Z"}}}}
    body = json.dumps(st, sort_keys=True, separators=(",", ":")).encode()
    ptype = "application/vnd.in-toto+json"
    pae = b"DSSEv1 %d %b %d %b" % (len(ptype), ptype.encode(), len(body), body)
    sig = Ed25519PrivateKey.from_private_bytes(MI.SEED).sign(pae)
    return {"payload": base64.b64encode(body).decode(), "payloadType": ptype,
            "signatures": [{"keyid": MI.KEYID, "sig": base64.b64encode(sig).decode()}]}


def main() -> int:  # noqa: C901, PLR0915 - one linear measurement, kept in order on purpose
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--go-probe", required=True, type=Path)
    ap.add_argument("--py", required=True, type=Path)
    ap.add_argument("--bin", required=True, type=Path)
    ap.add_argument("--out", type=Path, default=HERE / "results")
    ap.add_argument("--inputs", type=Path, default=HERE / "inputs")
    a = ap.parse_args()
    b = a.bin
    cosign, crane, registry = b / "cosign", b / "crane", b / "registry"
    guacone, guacgql = b / "guacone-linux-amd64", b / "guacgql-linux-amd64"
    a.out.mkdir(parents=True, exist_ok=True)
    scratch = Path(tempfile.mkdtemp(prefix="z225-"))
    env = {**os.environ, "HOME": str(scratch / "home")}
    (scratch / "home").mkdir()
    procs = []
    try:
        # 1. registry and image
        rport = _free_port()
        procs.append(subprocess.Popen([str(registry), "-port", str(rport)], stdout=subprocess.DEVNULL,
                                      stderr=subprocess.DEVNULL))
        _wait(f"http://127.0.0.1:{rport}/v2/")
        reg = f"localhost:{rport}"
        (scratch / "layer.tar").write_bytes(_layer_tar())

        def push(repo: str) -> str:
            r = _run([crane, "append", "-f", scratch / "layer.tar", "-t", f"{reg}/{repo}:z225", "--insecure"])
            if r.returncode != 0:
                raise RuntimeError(r.stderr)
            return _run([crane, "digest", f"{reg}/{repo}:z225", "--insecure"]).stdout.strip()

        image = push("z225/img")
        image_hex = image.split(":", 1)[1]

        # 2. inputs
        if a.inputs.exists():
            shutil.rmtree(a.inputs)
        r = _run([sys.executable, HERE / "make_inputs.py", "--image-digest", image, "--out", a.inputs])
        if r.returncode != 0:
            raise RuntimeError(r.stderr)
        meta = json.loads((a.inputs / "inputs.json").read_text())
        pub_b64 = meta["public_key_b64"]
        keyid = meta["keyid_of_the_keyid_control"]
        # cosign and GUAC take the key as PEM: the RFC 8410 SubjectPublicKeyInfo of an Ed25519 key is a
        # fixed 12-byte prefix and the 32 raw bytes, so no key object is built here.
        spki = bytes.fromhex("302a300506032b6570032100") + decode_b64(pub_b64)
        (scratch / "pub.pem").write_text("-----BEGIN PUBLIC KEY-----\n" + base64.b64encode(spki).decode()
                                         + "\n-----END PUBLIC KEY-----\n")
        cells = {**{k: (v, False) for k, v in meta["attestations"].items()},
                 **{"control." + k: (v, True) for k, v in meta["controls"].items()}}
        blobs = {"receipt": [a.inputs / "receipt_binder.json"],
                 "public-model": [a.inputs / "public_model.txt"],
                 "release-gate": ["--digest", image_hex, "--digestAlg", "sha256"]}

        # 3. probes
        files = [str(a.inputs / f) for f, _c in cells.values()]
        go = {json.loads(ln)["file"].rsplit("/", 1)[-1]: json.loads(ln)
              for ln in _run([a.go_probe, pub_b64, *files]).stdout.splitlines()}
        py = {json.loads(ln)["file"]: json.loads(ln)
              for ln in _run([a.py, HERE / "probe_python.py", decode_b64(pub_b64).hex(), keyid,
                              *files]).stdout.splitlines()}

        # 4. GUAC server and its control
        gport = _free_port()
        procs.append(subprocess.Popen([str(guacgql), "--gql-listen-port", str(gport), "--gql-backend",
                                       "keyvalue"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        _wait(f"http://127.0.0.1:{gport}/query")

        def guac(name: str, envelope: Path) -> dict:
            d = scratch / "guac" / name
            d.mkdir(parents=True)
            shutil.copy(envelope, d / envelope.name)
            before = _graph(gport)
            r = _run([guacone, "collect", "files", d, "--gql-addr", f"http://127.0.0.1:{gport}/query",
                      "--verifier-key-path", scratch / "pub.pem", "--verifier-key-id", keyid], env=env)
            log = r.stdout + r.stderr
            msgs = [json.loads(ln).get("msg", "") for ln in log.splitlines() if ln.startswith("{")]
            after = _graph(gport)
            return {"exit": r.returncode,
                    "ingested": next((m.replace(str(scratch), "<scratch>") for m in msgs
                                      if "were successful" in m or "ingestion complete" in m.lower()), ""),
                    "error": next((m for m in msgs if m.startswith("emit error")), ""),
                    "graph_added": {k: (sorted(set(after[k]) - set(before[k])) if k == "artifacts"
                                        else after[k] - before[k]) for k in after}}

        (scratch / "slsa_control.json").write_text(json.dumps(_slsa_control(image_hex)))
        guac_control = guac("control.slsa", scratch / "slsa_control.json")
        guac_ok = bool(guac_control["graph_added"]["HasSLSA"])

        # 5. per cell: cosign and GUAC
        rows = {}
        for cell, (fname, is_control) in cells.items():
            envelope = a.inputs / fname
            payload = json.loads(decode_b64(json.loads(envelope.read_text())["payload"]))
            ptype = payload["predicateType"]
            profile = cell.rsplit(".", 1)[-1]
            repo = "z225/" + cell.replace(".", "-")
            digest = push(repo)
            att = _run([cosign, "attach", "attestation", "--allow-http-registry", "--attestation", envelope,
                        f"{reg}/{repo}@{digest}"], env=env)
            img = _run([cosign, "verify-attestation", "--allow-http-registry", "--key", scratch / "pub.pem",
                        "--type", ptype, "--insecure-ignore-tlog=true", f"{reg}/{repo}@{digest}"], env=env)
            blob = _run([cosign, "verify-blob-attestation", "--key", scratch / "pub.pem", "--type", ptype,
                         "--insecure-ignore-tlog=true", "--signature", envelope, *blobs[profile]], env=env)
            rows[cell] = {
                "file": fname, "control": is_control, "predicate_type": ptype,
                "payload_type": json.loads(envelope.read_text())["payloadType"],
                "has_contentRootAlg": "contentRootAlg" in payload,
                "has_keyid": any("keyid" in s for s in json.loads(envelope.read_text())["signatures"]),
                "go": {**go.get(fname, {}), "file": fname}, "python": py.get(fname),
                "cosign_verify_attestation": {"attach_exit": att.returncode,
                                              "attach_last_line": _last_error(att.stderr),
                                              "exit": img.returncode, "last_line": _last_error(img.stderr)},
                "cosign_verify_blob_attestation": {"exit": blob.returncode, "last_line": _last_error(blob.stderr)},
                "guac": guac(cell, envelope) if guac_ok else "NOT MEASURABLE: the GUAC control did not ingest",
            }

        # 6. versions
        def ver(cmd) -> str:
            r = _run(cmd)
            return (r.stdout + r.stderr).strip()

        def sha(p: Path) -> str:
            return hashlib.sha256(p.read_bytes()).hexdigest()

        versions = {
            "cosign": {"version": ver([cosign, "version", "--json"]), "sha256": sha(cosign)},
            "guacone": {"version": ver([guacone, "--version"]), "sha256": sha(guacone)},
            "guacgql": {"sha256": sha(guacgql)},
            "crane": {"version": ver([crane, "version"]), "sha256": sha(crane)},
            "go_probe_build": [ln.strip() for ln in ver(["go", "version", "-m", a.go_probe]).splitlines()[1:]
                               if ln.strip().startswith(("dep", "mod"))],
            "go_toolchain": ver(["go", "version", "-m", a.go_probe]).splitlines()[0].rsplit(" ", 1)[-1],
            "python_probe_packages": [ln for ln in ver([a.py, "-m", "pip", "list", "--format=freeze"]).splitlines()
                                      if "==" in ln],
        }
        result = {"tool": "tools/intoto_external/run.py", "measured_on": time.strftime("%Y-%m-%d", time.gmtime()),
                  "image": image, "guac_control": guac_control, "not_applicable": meta["not_applicable"],
                  "rows": rows, "versions": versions}
        text = json.dumps(result, indent=2, sort_keys=True) + "\n"
        for path, name in ((a.inputs.resolve(), "inputs"), (scratch, "<scratch>"), (HERE, "tools/intoto_external")):
            text = text.replace(str(path), name)
        (a.out / "results.json").write_text(text)
        print(json.dumps({c: {"go_dsse": (r["go"] or {}).get("dsse_verified"),
                              "go_strict": not (r["go"] or {}).get("statement_strict_parse_error"),
                              "py_dsse": (r["python"] or {}).get("dsse_verified"),
                              "py_strict": not (r["python"] or {}).get("statement_strict_parse_error"),
                              "cosign_img": r["cosign_verify_attestation"]["exit"],
                              "cosign_blob": r["cosign_verify_blob_attestation"]["exit"],
                              "guac": r["guac"] if isinstance(r["guac"], str) else r["guac"]["graph_added"]}
                          for c, r in rows.items()}, indent=1))
        return 0
    finally:
        for p in procs:
            p.terminate()
        shutil.rmtree(scratch, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
