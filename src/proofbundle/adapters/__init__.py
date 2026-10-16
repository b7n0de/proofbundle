"""Adapters that map an eval framework's EXPORTED result JSON to an eval claim.

Each adapter reads a result file from disk and never imports the framework, so they
add no runtime dependency. The output-format mapping is bound to a framework version;
each fixture in tests/fixtures documents its source + version.
"""
from .inspect_ai import from_inspect_ai_log
from .eee import from_eee_dataset
from .junit_ctrf import (ReportRefused, from_ctrf_json, from_junit_xml, read_ctrf_json, read_junit_xml,
                         verify_test_receipt)
from .lm_eval import from_lm_eval_results
from .promptfoo import from_promptfoo_results
from .samples import samples_from_lm_eval_jsonl, samples_from_promptfoo_results

__all__ = ["from_lm_eval_results", "from_inspect_ai_log", "from_eee_dataset",
           "from_promptfoo_results", "from_junit_xml", "from_ctrf_json",
           "read_junit_xml", "read_ctrf_json", "verify_test_receipt", "ReportRefused",
           "samples_from_lm_eval_jsonl", "samples_from_promptfoo_results"]
