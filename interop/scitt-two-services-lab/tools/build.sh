#!/bin/bash
# Builds both images with the rootless daemon under nice. The ledger as docker/build.sh does (docker/Dockerfile
# unchanged), scittles from its own Dockerfile. The guard stops a build when the runner check twice says not free.
set -u
. /mnt/bigstore/claude_scratch/z389/n113/scitt_interop_labor/en/tools/common.sh
P=$M/build
mkdir -p "$P"
check_rootless || exit 9
wait_until_free "$P/build.log" || exit 7
[ "$(git -C "$LEDGER" rev-parse HEAD)" = "$LEDGER_HEAD" ] || { echo "STOP: ledger not at $LEDGER_HEAD"; exit 9; }
[ "$(git -C "$SCITTLES" rev-parse HEAD)" = "$SCITTLES_HEAD" ] || { echo "STOP: scittles not at $SCITTLES_HEAD"; exit 9; }
[ -z "$(git -C "$LEDGER" status --short)" ] && [ -z "$(git -C "$SCITTLES" status --short)" ] || { echo "STOP: tree not clean"; exit 9; }
build() {  # build <name> <folder> <dockerfile> <image> [build-args...]
  local name=$1 folder=$2 df=$3 img=$4; shift 4
  echo "$(date -u +%FT%TZ) $name build start" | tee -a "$P/build.log"
  (cd "$folder" && DOCKER_BUILDKIT=1 nice -n 15 docker build -t "$img" -f "$df" --provenance=false "$@" . \
     > "$P/build_$name.log" 2>&1) &
  local bp=$!
  guard "$bp" "pid:$bp" "$P/build.log" &
  wait "$bp"; local brc=$?
  echo "$(date -u +%FT%TZ) $name build exit=$brc" | tee -a "$P/build.log"
  grep -q STOP "$P/build.log" && exit 7
  [ "$brc" -eq 0 ] || exit 6
  docker image inspect "$img" --format "$name {{.Id}} {{.Size}}" | tee -a "$P/build.log"
}
V=$(git -C "$LEDGER" describe --tags --long --always)
E=$(git -C "$LEDGER" show -s --format=%ct HEAD)
echo "ledger version=$V epoch=$E" | tee -a "$P/build.log"
build ledger "$LEDGER" docker/Dockerfile "$IMG_LEDGER" --build-arg SOURCE_DATE_EPOCH="$E" --build-arg SCITT_VERSION_OVERRIDE="$V"
build scittles "$SCITTLES" Dockerfile "$IMG_SCITTLES"
docker run --rm --network none "$IMG_SCITTLES" python -m pip freeze > "$P/scittles_pip_freeze.txt" 2>&1
echo "$(date -u +%FT%TZ) pip freeze rc=$? $(wc -l < "$P/scittles_pip_freeze.txt") lines" | tee -a "$P/build.log"
