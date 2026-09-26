"""tools/measurements/merkle_two_readings.py says exit 2 on a usage error, and 1 when the two readings
differ. A checkout without the module raised `SystemExit(<text>)`, which exits 1: a wrong path read
as "two roots" (found by a sweep for that class, 2026-09-26)."""
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


def test_control_this_checkout_is_measured():
    r = subprocess.run([sys.executable, str(SCRIPT), "--checkout", str(ROOT), "--json"],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode in (0, 1), r.stdout + r.stderr
    assert '"verdict"' in r.stdout
