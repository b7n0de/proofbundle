#!/bin/bash
# The whole run in one: images (from cache when unchanged), statements, the ledger, scittles as built, the scittles
# variant, the cause measurement and the table.
set -u
. /mnt/bigstore/claude_scratch/z389/n113/scitt_interop_labor/en/tools/common.sh
test -e "$M" && { echo "STOP: $M exists"; exit 9; }
mkdir -p "$M"
bash "$T/build.sh" || exit $?
bash "$T/build_variant.sh" || exit $?
"$PY" -I -B "$T/make_statements.py" "$FOLDER03" "$M/statements" > "$M/statements.log" 2>&1 || exit 5
docker run --rm -i --network none -v "$M/statements:/s:ro" "$IMG_SCITTLES" python - > "$M/scittles_cause.txt" 2>&1 <<'INNER'
from importlib.metadata import version
import cbor2
print("cbor2", version("cbor2"), "pycose", version("pycose"))
raw = open("/s/D1.cbor", "rb").read()
obj = cbor2.loads(raw)
print("top", type(obj).__name__, "tag", getattr(obj, "tag", None), "content", type(obj.value).__name__)
from pycose.messages import Sign1Message
try:
    Sign1Message.decode(raw)
    print("decode ok")
except Exception as e:
    print("decode error", type(e).__name__, e)
INNER
bash "$T/run_ledger.sh"
bash "$T/run_scittles.sh" scittles "$IMG_SCITTLES"
bash "$T/run_scittles.sh" scittles_cbor2_5 "$IMG_SCITTLES_VARIANT"
"$PY" -I -B "$T/summarize.py" "$M" > /dev/null
echo "$(date -u +%FT%TZ) run_all end"
