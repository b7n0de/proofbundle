#!/bin/bash
# One fresh ledger node from the image at 6531df8a, governance as docker/run-dev.sh does it with pyscitt
# "local_development" (unauthenticated, policy: a CWT issuer is present), then the client on the host against
# 127.0.0.1:18443. Foreign code runs only in containers; mounts are the work folder and the source tree (read only), no
# socket, no credentials. The node's processes get nice 15 (renice through docker top).
set -u
. /mnt/bigstore/claude_scratch/z389/n113/scitt_interop_labor/en/tools/common.sh
O=$M/ledger
W=$O/workspace
test -e "$O" && { echo "STOP: $O exists"; exit 9; }
check_rootless || exit 9
mkdir -p "$W" "$O/pipcache"
log() { echo "$(date -u +%FT%TZ) $*" | tee -a "$O/run.log"; }
wait_until_free "$O/run.log" || exit 7
PYIMG=$(docker image inspect python:3.12 --format '{{index .RepoDigests 0}}')
log "start image=$(docker image inspect "$IMG_LEDGER" --format '{{.Id}}') python=$PYIMG"
cp "$LEDGER/docker/dev-config.tmpl.json" "$W/dev-config.json"
sed -i "s/%CCF_PORT%/8000/g" "$W/dev-config.json"
cp -r "$LEDGER/app/constitution" "$W/"
docker run --rm --name b7lab-keygen -v "$LEDGER:/src:ro" -v "$W:/ws" -w /ws "$PYIMG" \
  bash /src/docker/keygenerator.sh --name member0 --gen-enc-key > "$O/keygen.log" 2>&1 || { log "STOP keygen"; exit 8; }
C=b7lab-ledger
docker run -d --name "$C" --memory=2g -p 127.0.0.1:18443:8000 -v "$W:/host" --entrypoint cchost "$IMG_LEDGER" \
  --config /host/dev-config.json --log-level info > "$O/ccf.id" 2>&1 || { log "STOP ccf start"; exit 8; }
for p in $(docker top "$C" -o pid | tail -n +2); do renice -n 15 -p "$p" >> "$O/renice.log" 2>&1; done
log "ccf $(cut -c1-12 "$O/ccf.id") renice: $(grep -c 'old priority' "$O/renice.log") processes"
docker run --rm -i --name b7lab-gov --network "container:$C" -v "$LEDGER:/src:ro" -v "$W:/ws:ro" \
  -v "$O/pipcache:/pipcache" -e PIP_CACHE_DIR=/pipcache "$PYIMG" bash -s > "$O/governance.log" 2>&1 <<'INNER'
set -eu
cp -r /src/pyscitt /tmp/pyscitt
python -m venv /tmp/venv && . /tmp/venv/bin/activate
pip install --disable-pip-version-check -q /tmp/pyscitt
pip freeze
n=0; until curl -s -f -k https://localhost:8000/node/network > /dev/null; do n=$((n+1)); [ $n -ge 120 ] && exit 3; sleep 1; done
scitt governance local_development --url https://localhost:8000 --member-key /ws/member0_privk.pem --member-cert /ws/member0_cert.pem
n=0; until curl -s -f -k https://localhost:8000/version > /dev/null; do n=$((n+1)); [ $n -ge 120 ] && exit 4; sleep 2; done
curl -s -k https://localhost:8000/version; echo
curl -s -k https://localhost:8000/configuration; echo
INNER
grc=$?
log "governance exit=$grc"
if [ "$grc" -eq 0 ]; then
  nice -n 15 "$PY" -I -B "$T/lab_client.py" ledger https://127.0.0.1:18443 "$FOLDER03" "$M/statements" "$O/result" \
    > "$O/client.log" 2>&1 &
  cp=$!
  guard "$cp" "pid:$cp" "$O/run.log" 1800 &
  wait "$cp"; log "client exit=$?"
fi
docker logs "$C" > "$O/ccf.log" 2>&1
docker stop "$C" > /dev/null 2>&1; docker rm "$C" > /dev/null 2>&1
log "ccf stopped and removed, end"
