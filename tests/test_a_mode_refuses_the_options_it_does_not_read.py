"""631 part 2, P2 group 1 of CODEX-DEFEKTSUCHE-630-KANDIDAT-01 (at 98b168b9): an option the chosen mode does not
read is refused, never silently dropped.

Measured at 063b4e22 with the throwaway example key and the released fixture
`tests/fixtures/eval_result_v0_1/envelope_legacy.json`: `intoto ... --verify --pub PUB` ended `=> OK`, exit 0, with
each of `--predicate-version v0.2`, `--predicate-version v0.1`, `--evaluator`, `--receipt-uri not-a-uri`, `--out`,
`--key`, `--new-key`, `--subject-profile`, `--subject-name` and `--subject-sha256`, exactly as without them; `svr
--verify` did the same with `--policy-uri`, `--policy-sha256`, `--out`, `--key` and `--new-key`; both exports took
`--pub` and wrote; `svr` wrote an SVR without a policy for `--policy-sha256` alone; an export without `--out` wrote
the new key and then failed with a generic TypeError text. Both README renderers rewrote a stale README and exited 0
for `--chek` or `--unknown-option`, and answered `--check --unknown-option` like `--check`. Controls: the same calls
without the extra option keep their verdicts, and the default export stays v0.1 with the receipt profile.
"""
from __future__ import annotations

import base64
import contextlib
import importlib.util
import io
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from proofbundle.cli import main
from proofbundle.evalclaim import build_eval_claim, emit_eval_receipt, issuer_fingerprint

REPO = Path(__file__).resolve().parents[1]
LEGACY = REPO / "tests/fixtures/eval_result_v0_1/envelope_legacy.json"
SIGNER = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))      # the throwaway example key
PUB = base64.b64encode(SIGNER.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
V01 = "https://b7n0de.com/attestation/eval-result/v0.1"


def _run(*argv) -> tuple[int, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main([str(a) for a in argv])
    return code, out.getvalue() + err.getvalue()


@pytest.fixture
def world(tmp_path):
    claim, _ = build_eval_claim(
        suite="safety-refusals", suite_version="1.2.0", metric="refusal_rate", comparator=">=", threshold="0.98",
        score="0.994", n=500, model_id="acme/secret-model-7b", dataset_id="acme/internal-redteam-set",
        issuer=issuer_fingerprint(SIGNER), timestamp="2026-07-05T12:00:00Z", model_salt=b"\x11" * 16,
        dataset_salt=b"\x11" * 16)
    receipt = tmp_path / "receipt.json"
    receipt.write_text(json.dumps(emit_eval_receipt(claim, SIGNER)), encoding="utf-8")
    key = tmp_path / "key.bin"
    key.write_bytes(bytes(range(32)))
    svr = tmp_path / "svr.json"
    assert _run("svr", receipt, "--out", svr, "--key", key)[0] == 0
    return {"dir": tmp_path, "receipt": receipt, "key": key, "svr": svr}


INTOTO_EXPORT = {
    "--predicate-version v0.2": ("--predicate-version", "v0.2"),
    "--predicate-version v0.1": ("--predicate-version", "v0.1"),
    "--evaluator": ("--evaluator", "https://example.com/evaluator"),
    "--receipt-uri": ("--receipt-uri", "not-a-uri"),
    "--out": ("--out", "{dir}/written.json"),
    "--key": ("--key", "{key}"),
    "--new-key": ("--new-key", "{dir}/new.bin"),
    "--subject-profile": ("--subject-profile", "public-model"),
    "--subject-profile receipt": ("--subject-profile", "receipt"),
    "--subject-name": ("--subject-name", "acme/open-model-7b"),
    "--subject-sha256": ("--subject-sha256", "e4" * 32),
}
SVR_EMIT = {
    "--policy-uri": ("--policy-uri", "https://example.com/policy"),
    "--policy-sha256": ("--policy-sha256", "ab" * 32),
    "--out": ("--out", "{dir}/written.json"),
    "--key": ("--key", "{key}"),
    "--new-key": ("--new-key", "{dir}/new.bin"),
}


def _filled(option: tuple, world) -> list[str]:
    return [part.format(dir=world["dir"], key=world["key"]) for part in option]


@pytest.mark.parametrize("name", sorted(INTOTO_EXPORT))
def test_intoto_verify_refuses_an_export_option(world, name):
    code, text = _run("intoto", LEGACY, "--verify", "--pub", PUB, *_filled(INTOTO_EXPORT[name], world))
    assert code == 2 and name.split()[0] in text and "=> OK" not in text, text
    assert not (world["dir"] / "written.json").exists() and not (world["dir"] / "new.bin").exists()


@pytest.mark.parametrize("name", sorted(SVR_EMIT))
def test_svr_verify_refuses_an_emit_option(world, name):
    code, text = _run("svr", world["svr"], "--verify", "--pub", PUB, *_filled(SVR_EMIT[name], world))
    assert code == 2 and name in text and "=> OK" not in text, text
    assert not (world["dir"] / "written.json").exists() and not (world["dir"] / "new.bin").exists()


@pytest.mark.parametrize("command", ["intoto", "svr"])
def test_an_export_refuses_pub_and_writes_nothing(world, command):
    out, new = world["dir"] / "att.json", world["dir"] / "new.bin"
    code, text = _run(command, world["receipt"], "--out", out, "--new-key", new, "--pub", PUB)
    assert code == 2 and "--pub" in text, text
    assert not out.exists() and not new.exists()


@pytest.mark.parametrize("command", ["intoto", "svr"])
def test_an_export_without_out_is_named_before_a_key_is_written(world, command):
    new = world["dir"] / "new.bin"
    code, text = _run(command, world["receipt"], "--new-key", new)
    assert code == 2 and "needs --out" in text, text
    assert not new.exists()


def test_svr_refuses_a_policy_digest_without_its_uri(world):
    out = world["dir"] / "s.json"
    code, text = _run("svr", world["receipt"], "--out", out, "--key", world["key"], "--policy-sha256", "ab" * 32)
    assert code == 2 and "--policy-uri" in text and not out.exists(), text


# --- controls ---------------------------------------------------------------------------------------------------

def test_control_the_verifiers_without_an_extra_option_keep_their_verdicts(world):
    assert _run("intoto", LEGACY, "--verify", "--pub", PUB)[0] == 0
    assert _run("svr", world["svr"], "--verify", "--pub", PUB)[0] == 0
    assert _run("intoto", LEGACY, "--verify")[0] == 2


def test_control_the_default_export_stays_v01_with_the_receipt_profile(world):
    out = world["dir"] / "att.json"
    code, text = _run("intoto", world["receipt"], "--out", out, "--key", world["key"])
    assert code == 0 and "(subject profile: receipt)" in text, text
    statement = json.loads(base64.b64decode(json.loads(out.read_text(encoding="utf-8"))["payload"]))
    assert statement["predicateType"] == V01
    assert _run("intoto", out, "--verify", "--pub", PUB)[0] == 0


def test_control_a_v02_export_and_a_policy_with_its_digest_are_written(world):
    out = world["dir"] / "att.json"
    code, text = _run("intoto", world["receipt"], "--out", out, "--key", world["key"], "--predicate-version", "v0.2",
                      "--evaluator", "https://example.com/evaluator")
    assert code == 0 and _run("intoto", out, "--verify", "--pub", PUB)[0] == 0, text
    svr = world["dir"] / "s.json"
    code, text = _run("svr", world["receipt"], "--out", svr, "--key", world["key"], "--policy-uri",
                      "https://example.com/policy", "--policy-sha256", "ab" * 32)
    assert code == 0, text
    statement = json.loads(base64.b64decode(json.loads(svr.read_text(encoding="utf-8"))["payload"]))
    assert statement["predicate"]["verifier"]["policy"] == {"uri": "https://example.com/policy",
                                                            "digest": {"sha256": "ab" * 32}}


# --- the README renderers -----------------------------------------------------------------------------------------

RENDERERS = ("tools/merkle_accumulator/render_runs.py", "benchmarks/runtime_baseline/render.py")


def _renderer(rel: str, tmp_path):
    spec = importlib.util.spec_from_file_location(f"_renderer_{Path(rel).stem}", REPO / rel)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    copy = tmp_path / "README.md"
    copy.write_bytes(module.README.read_bytes())
    module.README = copy
    marker = f"<!-- {module.BLOCKS[0][0]}: written by {Path(rel).name} -->".encode()
    current = copy.read_bytes()
    assert current.count(marker) == 1
    return module, copy, current, current.replace(marker, marker + b"\nSTALE")


def _call(module, argv) -> int:
    with contextlib.redirect_stderr(io.StringIO()):
        return module.main(argv)


@pytest.mark.parametrize("argv", [["--chek"], ["--unknown-option"], ["--check", "--unknown-option"], ["--check", "--check"]],
                         ids=["a misspelt check", "an unknown option", "check with an unknown option", "check twice"])
@pytest.mark.parametrize("rel", RENDERERS)
def test_a_renderer_refuses_an_argument_it_does_not_read(tmp_path, rel, argv):
    module, copy, _current, stale = _renderer(rel, tmp_path)
    copy.write_bytes(stale)
    assert _call(module, argv) == 2
    assert copy.read_bytes() == stale, "a refused call writes nothing"


@pytest.mark.parametrize("rel", RENDERERS)
def test_control_a_renderer_checks_and_writes_as_documented(tmp_path, rel):
    module, copy, current, stale = _renderer(rel, tmp_path)
    assert _call(module, ["--check"]) == 0
    copy.write_bytes(stale)
    assert _call(module, ["--check"]) == 1 and copy.read_bytes() == stale
    assert _call(module, []) == 0 and copy.read_bytes() == current
