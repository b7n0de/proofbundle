#!/usr/bin/env python3
"""Stand-in for the pb_verify_rs binary that records each call, then runs the real binary.

Environment: RECORD_TARGET is the binary to run, RECORD_LOG the JSON-lines file to append to. Each
line holds the arguments, the bytes of every argument that names an existing file, and the exit
code, standard output and standard error of the real binary, so the call can be replayed later
where the files no longer exist, for example in a browser.
"""
import base64
import json
import os
import subprocess
import sys


def main() -> int:
    files = {}
    for arg in sys.argv[1:]:
        if os.path.isabs(arg) and os.path.isfile(arg):
            with open(arg, "rb") as handle:
                files[arg] = base64.b64encode(handle.read()).decode("ascii")
    proc = subprocess.run([os.environ["RECORD_TARGET"], *sys.argv[1:]], capture_output=True, check=False)
    with open(os.environ["RECORD_LOG"], "a", encoding="utf-8") as log:
        log.write(json.dumps({"argv": sys.argv[1:], "files": files, "exit": proc.returncode,
                              "stdout": base64.b64encode(proc.stdout).decode("ascii"),
                              "stderr": base64.b64encode(proc.stderr).decode("ascii")}) + "\n")
    sys.stdout.buffer.write(proc.stdout)
    sys.stderr.buffer.write(proc.stderr)
    return proc.returncode


if __name__ == "__main__":
    sys.exit(main())
