#!/bin/bash
# scittles: one fresh container with its own database per statement ("fresh"), then one container with all statements
# in a fixed order ("one_database"), because scittles keys an entry by the SHA-256 of the payload. Settings as
# shipped; port 127.0.0.1:18000 only. Processes with nice 15 (renice).
# Usage: run_scittles.sh [name of the run] [image]
set -u
. /mnt/bigstore/claude_scratch/z389/n113/scitt_interop_labor/en/tools/common.sh
O=$M/${1:-scittles}
IMG=${2:-$IMG_SCITTLES}
test -e "$O" && { echo "STOP: $O exists"; exit 9; }
check_rootless || exit 9
mkdir -p "$O"
log() { echo "$(date -u +%FT%TZ) $*" | tee -a "$O/run.log"; }
wait_until_free "$O/run.log" || exit 7
log "start image=$(docker image inspect "$IMG" --format '{{.Id}}')"
start() {  # start <name>
  docker run -d --name "b7lab-scittles-$1" --memory=1g -p 127.0.0.1:18000:8000 "$IMG" > "$O/$1.id" 2>&1 || return 8
  for p in $(docker top "b7lab-scittles-$1" -o pid | tail -n +2); do renice -n 15 -p "$p" >> "$O/renice.log" 2>&1; done
  local n=0
  until curl -s -f -o /dev/null http://127.0.0.1:18000/.well-known/transparency-configuration; do
    n=$((n + 1)); [ "$n" -ge 60 ] && return 4; sleep 1
  done
}
stop() {
  docker logs "b7lab-scittles-$1" > "$O/$1.container.log" 2>&1
  docker stop "b7lab-scittles-$1" > /dev/null 2>&1; docker rm "b7lab-scittles-$1" > /dev/null 2>&1
}
NAMES=$("$PY" -I -c "import json,sys; print(' '.join(json.load(open(sys.argv[1]))['statements']))" "$M/statements/statements.json")
for n in $NAMES; do
  start "$n" || { log "STOP start $n"; stop "$n"; exit 8; }
  nice -n 15 "$PY" -I -B "$T/lab_client.py" scittles http://127.0.0.1:18000 "$FOLDER03" "$M/statements" \
    "$O/fresh/$n" --only "$n" > "$O/fresh_$n.client.log" 2>&1
  log "fresh $n client exit=$?"
  stop "$n"
done
start one_database || { log "STOP start one_database"; stop one_database; exit 8; }
nice -n 15 "$PY" -I -B "$T/lab_client.py" scittles http://127.0.0.1:18000 "$FOLDER03" "$M/statements" \
  "$O/one_database" > "$O/one_database.client.log" 2>&1
log "one_database client exit=$?"
stop one_database
log "end"
