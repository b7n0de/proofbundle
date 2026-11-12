# Shared values and guards of the two-services lab (sourced with `.`).
# DOCKER_HOST points at the rootless daemon here only; DOCKER_CONFIG at a folder of our own that holds the buildx
# plugin, so ~/.docker is not touched.
export DOCKER_HOST=unix:///run/user/1000/docker.sock
export DOCKER_CONFIG=/mnt/bigstore/claude_scratch/z389/n113/docker1/messung/cli
L=/mnt/bigstore/claude_scratch/z389/n113/scitt_interop_labor
T=$L/en/tools
M=$L/en/measurement
Q=$L/quellen
LEDGER=$Q/ledger_6531df8a
LEDGER_HEAD=6531df8a31ca563951a3a21813b9dc1abf9dd8bb
SCITTLES=$Q/scittles
SCITTLES_HEAD=6653ab2da4ef5cebf5a02688be124c5759087b30
IMG_LEDGER=b7lab/scitt-ccf-ledger:6531df8a
IMG_SCITTLES=b7lab/scittles:6653ab2d
IMG_SCITTLES_VARIANT=b7lab/scittles:6653ab2d-cbor2-5
FOLDER03=/mnt/bigstore/claude_scratch/z389/n113/liste_kayode_04/archiv_30c93494/interop/scitt-statement-identification-03
PY=/home/konrad/proofbundle/.venv/bin/python

check_rootless() {
  case "$(docker info --format '{{.SecurityOptions}}' 2>/dev/null)" in
    *name=rootless*) return 0 ;;
    *) echo "STOP: the daemon behind $DOCKER_HOST is not rootless"; return 1 ;;
  esac
}

# Asks the machine's runner check every 30 s. Two answers in a row other than "frei" (free), or more than $4 seconds
# (default 2 h), stop the part: a container of ours (prefix b7lab-) is stopped, a PID is ended. Ends with PID $1.
guard() {
  local pid=$1 target=$2 log=$3 max=${4:-7200} no=0 z reason t0
  t0=$(date +%s)
  while test -d "/proc/$pid"; do
    z="$(cd /home/konrad/2bedone && timeout --foreground 60 python3 scripts/b7_vor_merge.py 2>/dev/null | tail -1)"
    if [ "$z" = "frei" ]; then no=0; else no=$((no + 1)); fi
    reason=""
    [ "$no" -ge 2 ] && reason="runner check says '$z'"
    [ $(( $(date +%s) - t0 )) -gt "$max" ] && reason="limit $max s"
    if [ -n "$reason" ]; then
      echo "$(date -u +%FT%TZ) STOP: $reason, stopping $target" >> "$log"
      case "$target" in
        b7lab-*) docker stop "$target" > /dev/null 2>&1 ;;
        pid:*) kill "${target#pid:}" 2> /dev/null ;;
      esac
      return 0
    fi
    sleep 30
  done
}

# Waits until the runner check says "frei" (every 60 s, at most 6 h).
wait_until_free() {
  local log=$1 z i
  for i in $(seq 1 360); do
    z="$(cd /home/konrad/2bedone && timeout --foreground 60 python3 scripts/b7_vor_merge.py 2>/dev/null | tail -1)"
    if [ "$z" = "frei" ]; then
      [ "$i" -gt 1 ] && echo "$(date -u +%FT%TZ) free after waiting" >> "$log"
      return 0
    fi
    [ "$i" -eq 1 ] && echo "$(date -u +%FT%TZ) waiting: runner check says '$z'" >> "$log"
    sleep 60
  done
  echo "$(date -u +%FT%TZ) STOP: not free for 6 h" >> "$log"
  return 1
}
