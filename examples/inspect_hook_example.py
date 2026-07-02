#!/usr/bin/env python3
"""Show the inspect_ai end-of-task hook emitting a signed receipt (opt-in), offline.

In a real run you just `pip install "proofbundle[inspect]"`, set PROOFBUNDLE_EMIT=1, and run `inspect eval` —
the hook fires automatically at end of task. Here we drive the hook on a committed real mockllm .eval log so
the example is deterministic. Needs `pip install "proofbundle[inspect,eval]"`."""
import asyncio
import json
import os
import tempfile
import types
from pathlib import Path

FX = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "inspect_logs" / "safety_refusal_demo.eval"


def main() -> int:
    from inspect_ai.log import read_eval_log

    from proofbundle import verify_bundle
    from proofbundle.inspect_hook import ProofbundleHooks

    out = tempfile.mkdtemp()
    os.environ.update(PROOFBUNDLE_EMIT="1", PROOFBUNDLE_OUT=out, PROOFBUNDLE_THRESHOLD="0")
    log = read_eval_log(str(FX), header_only=True)
    data = types.SimpleNamespace(log=log, eval_id="capitals", run_id="r", eval_set_id=None)
    asyncio.run(ProofbundleHooks().on_task_end(data))
    files = list(Path(out).glob("*.json"))
    ok = bool(files) and verify_bundle(json.loads(files[0].read_text())).ok
    print("=> OK" if ok else "=> FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
