"""tools/measurements/merkle_two_readings.py says exit 2 on a usage error, and 1 when the two readings
differ. A checkout without the module raised `SystemExit(<text>)`, which exits 1: a wrong path read
as "two roots" (found by a sweep for that class, 2026-09-26)."""
import json
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "measurements" / "merkle_two_readings.py"


def test_a_checkout_without_the_module_is_a_usage_error_exit_2():
    with tempfile.TemporaryDirectory(prefix="merkle-no-checkout-") as tmp:
        r = subprocess.run([sys.executable, str(SCRIPT), "--checkout", tmp], capture_output=True,
                           text=True, timeout=60)
    assert r.returncode == 2, r.stdout + r.stderr
    assert "no proofbundle/merkle.py under" in r.stderr


def test_a_module_that_does_not_import_is_a_stop_exit_2_not_two_roots():
    with tempfile.TemporaryDirectory(prefix="merkle-broken-") as tmp:
        pkg = pathlib.Path(tmp) / "src" / "proofbundle"
        pkg.mkdir(parents=True)
        (pkg / "__init__.py").write_text("", encoding="utf-8")
        (pkg / "merkle.py").write_text("def broken(:\n    pass\n", encoding="utf-8")
        r = subprocess.run([sys.executable, "-B", str(SCRIPT), "--checkout", tmp], capture_output=True,
                           text=True, timeout=60)
    assert r.returncode == 2, r.stdout + r.stderr
    assert "does not import: SyntaxError" in r.stderr and "Traceback" not in r.stderr


def test_a_module_that_raises_when_called_is_a_stop_exit_2_not_two_roots():
    """Run 7 of the stack lens: the import succeeded and the call raised, one frame deeper."""
    for label, body in (("raises in merkle_tree_hash",
                         "def merkle_tree_hash(e):\n    raise ValueError('boom')\ndef leaf_hash(e):\n    return b'y'\n"),
                        ("has no leaf_hash", "def merkle_tree_hash(e):\n    return b'x'\n")):
        with tempfile.TemporaryDirectory(prefix="merkle-raises-") as tmp:
            pkg = pathlib.Path(tmp) / "src" / "proofbundle"
            pkg.mkdir(parents=True)
            (pkg / "__init__.py").write_text("", encoding="utf-8")
            (pkg / "merkle.py").write_text(body, encoding="utf-8")
            r = subprocess.run([sys.executable, "-B", str(SCRIPT), "--checkout", tmp], capture_output=True,
                               text=True, timeout=60)
        assert r.returncode == 2, (label, r.stdout + r.stderr)
        assert "does not measure" in r.stderr and "Traceback" not in r.stderr, label


def _run_with(body: str, *extra: str) -> subprocess.CompletedProcess:
    with tempfile.TemporaryDirectory(prefix="merkle-exits-") as tmp:
        pkg = pathlib.Path(tmp) / "src" / "proofbundle"
        pkg.mkdir(parents=True)
        (pkg / "__init__.py").write_text("", encoding="utf-8")
        (pkg / "merkle.py").write_text(body, encoding="utf-8")
        return subprocess.run([sys.executable, "-B", str(SCRIPT), "--checkout", tmp, *extra],
                              capture_output=True, text=True, timeout=60)


def test_a_module_that_ends_the_process_is_a_stop_exit_2_whatever_code_it_chose():
    """Run 8 of the stack lens: `SystemExit` is not an `Exception`. `sys.exit(1)` on import ended the
    tool with 1 and no output, and `sys.exit(0)` in a call would read as "the readings agree"."""
    cases = (("exit 1 on import", "import sys\nsys.exit(1)\n", "does not import: SystemExit"),
             ("exit 0 when called",
              "import sys\ndef merkle_tree_hash(e):\n    sys.exit(0)\ndef leaf_hash(e):\n    return b'y'\n",
              "does not measure: SystemExit"),
             ("exit with a text when called",
              "def merkle_tree_hash(e):\n    raise SystemExit('stop')\ndef leaf_hash(e):\n    return b'y'\n",
              "does not measure: SystemExit: stop"))
    for label, body, said in cases:
        r = _run_with(body)
        assert r.returncode == 2, (label, r.returncode, r.stdout + r.stderr)
        assert said in r.stderr and "Traceback" not in r.stderr, (label, r.stderr)


def test_what_the_module_prints_does_not_break_the_json_document():
    body = ("print('hello from import')\n"
            "import hashlib\n"
            "def leaf_hash(e):\n    return hashlib.sha256(bytes([0]) + e).digest()\n"
            "def merkle_tree_hash(e):\n    return hashlib.sha256(b''.join(e)).digest()\n")
    r = _run_with(body, "--json")
    assert r.returncode in (0, 1), r.stdout + r.stderr
    assert json.loads(r.stdout)["schema"] == "proofbundle.merkle_two_readings.v1"
    assert "hello from import" in r.stderr and "hello from import" not in r.stdout


def test_control_this_checkout_is_measured():
    r = subprocess.run([sys.executable, str(SCRIPT), "--checkout", str(ROOT), "--json"],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode in (0, 1), r.stdout + r.stderr
    assert '"verdict"' in r.stdout


# The module runs in a child process, and this process decides (a review of the stack at 1ecc2aca,
# measured 2026-09-26). Each case below ended in-process with a traceback and exit 1, with a line
# after the JSON document, or with exit 0 and no output.

GOOD = ("import hashlib\n"
        "def leaf_hash(e):\n    return hashlib.sha256(bytes([0]) + e).digest()\n"
        "def merkle_tree_hash(e):\n    return hashlib.sha256(b''.join(e)).digest()\n")


def _raising_in_the_call(prelude: str, statement: str) -> str:
    return prelude + GOOD.replace("def merkle_tree_hash(e):\n", f"def merkle_tree_hash(e):\n    {statement}\n")


def test_a_base_exception_from_the_module_is_a_stop_exit_2():
    """`GeneratorExit` and `asyncio.CancelledError` are no `Exception`; neither is a `KeyboardInterrupt`
    the module raises, which ends only the child."""
    cases = (("CancelledError in a call", _raising_in_the_call("import asyncio\n", "raise asyncio.CancelledError()"),
              "does not measure: CancelledError"),
             ("GeneratorExit in a call", _raising_in_the_call("", "raise GeneratorExit()"),
              "does not measure: GeneratorExit"),
             ("KeyboardInterrupt in a call", _raising_in_the_call("", "raise KeyboardInterrupt()"),
              "does not measure: KeyboardInterrupt"),
             ("GeneratorExit on import", "raise GeneratorExit()\n", "does not import: GeneratorExit"))
    for label, body, said in cases:
        r = _run_with(body, "--json")
        assert r.returncode == 2, (label, r.returncode, r.stdout + r.stderr)
        assert said in r.stderr and "Traceback" not in r.stderr, (label, r.stderr)
        assert r.stdout == "", (label, r.stdout)


def test_a_root_is_read_as_the_bytes_the_module_returned():
    """A `bytes` subclass whose `hex()` returns an object broke `json.dumps`; the root's bytes are what
    was measured. A value that is not bytes at all is no root."""
    body = GOOD + ("class Odd(bytes):\n    def hex(self):\n        return object()\n"
                   "_plain = merkle_tree_hash\n"
                   "def merkle_tree_hash(e):\n    return Odd(_plain(e))\n")
    r = _run_with(body, "--json")
    assert r.returncode in (0, 1), r.stdout + r.stderr
    import hashlib
    entries = [e.encode() for e in json.loads(r.stdout)["entries"]]
    assert json.loads(r.stdout)["reading_a_section_2_1"] == hashlib.sha256(b"".join(entries)).hexdigest()
    r = _run_with(GOOD + "_plain = merkle_tree_hash\ndef merkle_tree_hash(e):\n    return _plain(e).hex()\n")
    assert r.returncode == 2 and "returned str, not bytes" in r.stderr, r.stdout + r.stderr


def test_output_after_the_document_or_on_file_descriptor_1_goes_to_stderr():
    cases = (("atexit", "import atexit\natexit.register(print, 'LATE LINE')\n"),
             ("a thread", "import threading, time\n"
                          "def _late():\n    time.sleep(0.2)\n    print('LATE LINE')\n"
                          "threading.Thread(target=_late).start()\n"),
             ("file descriptor 1", "import os\nos.write(1, b'LATE LINE\\n')\n"))
    for label, prelude in cases:
        r = _run_with(prelude + GOOD, "--json")
        assert r.returncode in (0, 1), (label, r.stdout + r.stderr)
        assert json.loads(r.stdout)["schema"] == "proofbundle.merkle_two_readings.v1", label
        assert "LATE LINE" in r.stderr and "LATE LINE" not in r.stdout, (label, r.stdout, r.stderr)


def test_a_child_that_ends_without_a_clean_record_is_a_stop_exit_2():
    """`os._exit(0)` in a call exited 0, "the readings agree", with no output."""
    cases = (("os._exit(0) in a call", _raising_in_the_call("import os\n", "os._exit(0)"), "left no record"),
             ("exit code 3 after the record", "import atexit, os\natexit.register(os._exit, 3)\n" + GOOD,
              "ended with exit code 3"),
             ("killed by a signal", _raising_in_the_call("import os, signal\n", "os.kill(os.getpid(), signal.SIGKILL)"),
              "ended with signal SIGKILL"),
             ("a second record on the channel",
              "import atexit, sys\n"
              "def _append():\n"
              "    with open(sys.argv[sys.argv.index('--child') + 1], 'a') as fh:\n"
              "        fh.write('{}')\n"
              "atexit.register(_append)\n" + GOOD, "does not read as one JSON document"))
    for label, body, said in cases:
        r = _run_with(body, "--json")
        assert r.returncode == 2, (label, r.returncode, r.stdout + r.stderr)
        assert said in r.stderr and r.stdout == "", (label, r.stdout, r.stderr)
