#!/bin/bash
# Builds the scittles variant with cbor2 below 6 (rootless, nice) and records its pip freeze and the difference.
set -u
. /mnt/bigstore/claude_scratch/z389/n113/scitt_interop_labor/en/tools/common.sh
P=$M/build
check_rootless || exit 9
wait_until_free "$P/build.log" || exit 7
echo "$(date -u +%FT%TZ) variant build start" | tee -a "$P/build.log"
(cd "$T/variant_cbor2_5" && DOCKER_BUILDKIT=1 nice -n 15 docker build -t "$IMG_SCITTLES_VARIANT" --provenance=false . \
   > "$P/build_variant.log" 2>&1)
echo "$(date -u +%FT%TZ) variant build exit=$? $(docker image inspect "$IMG_SCITTLES_VARIANT" --format '{{.Id}}')" | tee -a "$P/build.log"
docker run --rm --network none "$IMG_SCITTLES_VARIANT" python -m pip freeze > "$P/scittles_variant_pip_freeze.txt" 2>&1
diff "$P/scittles_pip_freeze.txt" "$P/scittles_variant_pip_freeze.txt" | tee -a "$P/build.log"
