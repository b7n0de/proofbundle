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
