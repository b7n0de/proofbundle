"""The demo examples run end-to-end (real fixtures -> receipt -> verify). Covers `make demo` (Phase B)."""
import importlib.util
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def _run_example(name):
    try:
        import inspect_ai.log  # noqa: F401  (inspect example needs it)
    except ImportError:
        if name == "inspect_receipt":
            raise unittest.SkipTest("inspect_ai not installed")
    spec = importlib.util.spec_from_file_location(name, REPO / "examples" / f"{name}.py")
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m.main()


class TestExamples(unittest.TestCase):
    def test_lm_eval_receipt_example(self):
        self.assertEqual(_run_example("lm_eval_receipt"), 0)

    def test_inspect_receipt_example(self):
        self.assertEqual(_run_example("inspect_receipt"), 0)
