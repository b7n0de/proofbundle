# /// script
# requires-python = ">=3.10"
# dependencies = ["proofbundle==6.1.0"]
# ///
"""MCP server of the proofbundle Claude Code plugin.

A stdio JSON-RPC 2.0 server with four tools. Each tool runs the proofbundle command line of the
package installed next to this interpreter (`python -m proofbundle.cli`), so a verdict and its
exit code are the package's own, not a re-implementation. The package comes from PyPI through the
pin in the script header above; `uv run --script` installs it.

The server writes only JSON-RPC messages to stdout, one per line. Diagnostics go to stderr.
"""
from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import tempfile
import uuid

SERVER_NAME = "proofbundle"
SERVER_VERSION = "0.1.0"
SUPPORTED_PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")
CLI_TIMEOUT_SECONDS = 120
KINDS_SIGNED = ("decision", "outcome")
KINDS_VERIFY = ("decision", "outcome", "bundle")

#: The verify exit-code contract of the proofbundle command line.
EXIT_MEANING = {
    0: "verified: signature and structure are valid under the given key",
    1: "verification failed: a signature or another cryptographic check did not hold",
    2: "malformed input: the file, the key or an option could not be read as required",
    3: "cryptography valid, but a supplied policy or anchor requirement was not met",
}

#: What a passing verification does and does not establish. Returned with every verify result so
#: the caller never has to infer it.
SCOPE = ("A pass proves that the holder of the given key signed exactly these bytes and that they "
         "were not changed since. It does not prove that any recorded value is true, and a verified "
         "ALLOW decision is a record of a decision, not an authorization.")

INSTRUCTIONS = ("Tools over the proofbundle package. verify_receipt checks a receipt against an issuer "
                "public key that the user supplies from a trusted source, never against a key taken "
                "from the receipt itself. inspect_receipt shows content without any verification.")


def _package_version() -> str:
    try:
        import proofbundle  # noqa: PLC0415
    except ImportError:
        return "not installed"
    return str(getattr(proofbundle, "__version__", "unknown"))


class ToolInputError(Exception):
    """An argument the tool cannot act on. Reported as a tool error, nothing is run."""


def _string(args: dict, name: str, *, required: bool = True) -> str | None:
    value = args.get(name)
    if value is None:
        if required:
            raise ToolInputError(f"missing required argument: {name}")
        return None
    if not isinstance(value, str) or not value:
        raise ToolInputError(f"argument {name} must be a non-empty string")
    return value


def _flag(args: dict, name: str) -> bool:
    value = args.get(name, False)
    if not isinstance(value, bool):
        raise ToolInputError(f"argument {name} must be true or false")
    return value


def _kind(args: dict, allowed: tuple[str, ...]) -> str:
    kind = _string(args, "kind")
    if kind not in allowed:
        raise ToolInputError(f"kind must be one of {', '.join(allowed)}")
    return kind


def _path(args: dict, name: str, *, required: bool = True) -> str | None:
    value = _string(args, name, required=required)
    return None if value is None else os.path.abspath(os.path.expanduser(value))


def _public_key(args: dict) -> str:
    value = _string(args, "public_key")
    try:
        raw = base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise ToolInputError("public_key must be standard base64") from exc
    if len(raw) != 32:
        raise ToolInputError(f"public_key must decode to 32 bytes, got {len(raw)}")
    return value


def _run_cli(argv: list[str]) -> dict:
    """Run the package's command line and return what it said, verbatim."""
    try:
        proc = subprocess.run([sys.executable, "-m", "proofbundle.cli", *argv], capture_output=True,
                              text=True, timeout=CLI_TIMEOUT_SECONDS, check=False)
    except subprocess.TimeoutExpired as exc:
        raise ToolInputError(f"proofbundle did not finish within {CLI_TIMEOUT_SECONDS} s") from exc
    result: dict = {"proofbundle_version": _package_version(), "command": ["proofbundle", *argv],
                    "exit_code": proc.returncode}
    try:
        result["output"] = json.loads(proc.stdout)
    except ValueError:
        result["output"] = proc.stdout
    if proc.stderr:
        result["stderr"] = proc.stderr
    return result


def tool_receipt_template(args: dict) -> tuple[dict, bool]:
    kind = _kind(args, KINDS_SIGNED)
    result = _run_cli([kind, "init"])
    # The template carries an all-zero identifier. A fresh one is offered next to it, so the caller
    # does not have to make one up.
    result["suggested_id"] = f"urn:uuid:{uuid.uuid4()}"
    return result, result["exit_code"] != 0


def _default_key_path() -> str:
    data = os.environ.get("CLAUDE_PLUGIN_DATA")
    if not data:
        raise ToolInputError("no key_path given and CLAUDE_PLUGIN_DATA is not set; pass key_path")
    keys = os.path.join(data, "keys")
    os.makedirs(keys, mode=0o700, exist_ok=True)
    return os.path.join(keys, "proofbundle-ed25519.key")


def tool_emit_receipt(args: dict) -> tuple[dict, bool]:
    kind = _kind(args, KINDS_SIGNED)
    out_path = _path(args, "out_path")
    if os.path.lexists(out_path):
        raise ToolInputError(f"out_path exists, refusing to overwrite: {out_path}")
    predicate = args.get("predicate")
    predicate_path = _path(args, "predicate_path", required=False)
    if (predicate is None) == (predicate_path is None):
        raise ToolInputError("pass exactly one of predicate (an object) or predicate_path")
    if predicate is not None and not isinstance(predicate, dict):
        raise ToolInputError("predicate must be a JSON object")
    key_path = _path(args, "key_path", required=False) or _default_key_path()
    key_created = not os.path.lexists(key_path)
    lenient = _flag(args, "lenient")

    with tempfile.TemporaryDirectory(prefix="proofbundle-mcp-") as scratch:
        if predicate is not None:
            predicate_path = os.path.join(scratch, "predicate.json")
            with open(predicate_path, "w", encoding="utf-8") as handle:
                json.dump(predicate, handle, ensure_ascii=False)
        argv = [kind, "emit", predicate_path, "--out", out_path,
                "--new-key" if key_created else "--key", key_path]
        if lenient:
            argv.append("--lenient")
        result = _run_cli(argv)
    failed = result["exit_code"] != 0
    result["out_path"] = out_path
    result["key_path"] = key_path
    result["key_created"] = key_created and os.path.exists(key_path)
    if not failed:
        from proofbundle.emit import load_signer  # noqa: PLC0415
        raw = load_signer(key_path).public_key().public_bytes_raw()
        result["public_key"] = base64.b64encode(raw).decode("ascii")
    return result, failed


def tool_verify_receipt(args: dict) -> tuple[dict, bool]:
    kind = _kind(args, KINDS_VERIFY)
    path = _path(args, "path")
    if kind == "bundle":
        argv = ["verify", path, "--json"]
    else:
        argv = [kind, "verify", path, "--pub", _public_key(args), "--json"]
        if _flag(args, "strict"):
            argv.append("--strict")
    policy_path = _path(args, "policy_path", required=False)
    if policy_path is not None:
        argv += ["--policy", policy_path]
    for name in ("aud", "nonce"):
        value = _string(args, name, required=False)
        if value is not None:
            argv += [f"--{name}", value]
    result = _run_cli(argv)
    result["meaning"] = EXIT_MEANING.get(result["exit_code"], "unknown exit code: treat as not verified")
    result["verified"] = result["exit_code"] == 0
    result["scope"] = SCOPE
    return result, False


def tool_inspect_receipt(args: dict) -> tuple[dict, bool]:
    kind = _kind(args, KINDS_SIGNED)
    result = _run_cli([kind, "inspect", _path(args, "path")])
    result["verified"] = False
    result["note"] = "inspect performs no verification; read this content only after verify_receipt passed"
    return result, result["exit_code"] != 0


_KIND_SIGNED = {"type": "string", "enum": list(KINDS_SIGNED)}
TOOLS = {
    "receipt_template": (tool_receipt_template, {
        "description": "Return a template predicate for a decision or outcome receipt, to be filled in "
                       "with the user's facts before emit_receipt, and a fresh identifier to use in it.",
        "inputSchema": {"type": "object", "properties": {"kind": _KIND_SIGNED}, "required": ["kind"],
                        "additionalProperties": False},
    }),
    "emit_receipt": (tool_emit_receipt, {
        "description": "Sign a decision or outcome predicate into a DSSE receipt file. Uses the key at "
                       "key_path, or creates a new Ed25519 key there when the file does not exist "
                       "(default: the plugin data directory). Never overwrites out_path. Returns the "
                       "public key to verify with.",
        "inputSchema": {"type": "object", "properties": {
            "kind": _KIND_SIGNED,
            "predicate": {"type": "object", "description": "the predicate as a JSON object"},
            "predicate_path": {"type": "string", "description": "path to a predicate JSON file"},
            "out_path": {"type": "string", "description": "where to write the signed receipt"},
            "key_path": {"type": "string", "description": "Ed25519 seed file; created when absent"},
            "lenient": {"type": "boolean", "description": "allow a predicate that is not strict-v0.1"},
        }, "required": ["kind", "out_path"], "additionalProperties": False},
    }),
    "verify_receipt": (tool_verify_receipt, {
        "description": "Verify a decision receipt, an outcome receipt or an evidence bundle with the "
                       "proofbundle command line. Returns the exit code, its meaning and the full JSON "
                       "report. For decision and outcome, public_key is the issuer key in base64 from a "
                       "source the user trusts.",
        "inputSchema": {"type": "object", "properties": {
            "kind": {"type": "string", "enum": list(KINDS_VERIFY)},
            "path": {"type": "string", "description": "path to the receipt or bundle file"},
            "public_key": {"type": "string", "description": "issuer Ed25519 public key, base64"},
            "policy_path": {"type": "string", "description": "optional trust policy JSON"},
            "strict": {"type": "boolean", "description": "enforce strict-v0.1 required fields"},
            "aud": {"type": "string", "description": "expected audience"},
            "nonce": {"type": "string", "description": "expected nonce"},
        }, "required": ["kind", "path"], "additionalProperties": False},
    }),
    "inspect_receipt": (tool_inspect_receipt, {
        "description": "Print the predicate of a decision or outcome receipt WITHOUT verifying it.",
        "inputSchema": {"type": "object", "properties": {
            "kind": _KIND_SIGNED,
            "path": {"type": "string", "description": "path to the receipt file"},
        }, "required": ["kind", "path"], "additionalProperties": False},
    }),
}


def _call_tool(params: dict) -> dict:
    name = params.get("name")
    args = params.get("arguments") or {}
    if name not in TOOLS:
        raise KeyError(name)
    try:
        if not isinstance(args, dict):
            raise ToolInputError("arguments must be an object")
        payload, is_error = TOOLS[name][0](args)
    except ToolInputError as exc:
        payload, is_error = {"error": str(exc)}, True
    return {"content": [{"type": "text", "text": json.dumps(payload, indent=2, ensure_ascii=False)}],
            "isError": is_error}


def handle(message: dict) -> dict | None:
    """Answer one JSON-RPC message. A notification (no id) gets no answer."""
    method = message.get("method")
    msg_id = message.get("id")
    params = message.get("params") or {}
    if msg_id is None:
        return None
    try:
        if method == "initialize":
            requested = params.get("protocolVersion")
            version = requested if requested in SUPPORTED_PROTOCOL_VERSIONS else SUPPORTED_PROTOCOL_VERSIONS[0]
            result = {"protocolVersion": version, "capabilities": {"tools": {}},
                      "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
                      "instructions": f"{INSTRUCTIONS} proofbundle package: {_package_version()}."}
        elif method == "ping":
            result = {}
        elif method == "tools/list":
            result = {"tools": [{"name": n, **spec} for n, (_, spec) in TOOLS.items()]}
        elif method == "tools/call":
            try:
                result = _call_tool(params)
            except KeyError:
                return {"jsonrpc": "2.0", "id": msg_id,
                        "error": {"code": -32602, "message": f"unknown tool: {params.get('name')}"}}
        else:
            return {"jsonrpc": "2.0", "id": msg_id,
                    "error": {"code": -32601, "message": f"method not found: {method}"}}
    except Exception as exc:  # noqa: BLE001 - one bad request must not end the session
        print(f"proofbundle mcp: {type(exc).__name__}: {exc}", file=sys.stderr)
        return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": -32603, "message": "internal error"}}
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def main() -> int:
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            message = json.loads(line)
        except ValueError:
            reply = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}
        else:
            if not isinstance(message, dict):
                reply = {"jsonrpc": "2.0", "id": None,
                         "error": {"code": -32600, "message": "invalid request: expected one object"}}
            else:
                reply = handle(message)
        if reply is not None:
            sys.stdout.write(json.dumps(reply, ensure_ascii=False) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
