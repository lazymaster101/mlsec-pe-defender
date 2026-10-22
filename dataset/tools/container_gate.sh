#!/bin/bash
# Container gate for one image: 1 CPU, 1 GiB, read-only rootfs, default bridge network with the
# port published on 127.0.0.1 only. Grades the course set over HTTP
# exactly like the harness, then pushes the largest goodware2 files (latency + cgroup peak).
# usage: container_gate.sh <image> <label>
set -u
IMG="$1"; LABEL="$2"
ROOT="/Users/seshadithyasaravanan/Desktop/CSCE 704/Model"
SET="$ROOT/csce704-blackbox-validation-100-samples-20261014-corrected"
PY="$ROOT/defender_product/.venv/bin/python"
NAME="gate_${LABEL}_$$"; PORT=$((19700 + RANDOM % 300))
docker rm -f "$NAME" >/dev/null 2>&1
T0=$(date +%s)
docker run -d --rm --name "$NAME" -m 1g --cpus 1 --read-only --tmpfs /tmp -p 127.0.0.1:$PORT:8080 "$IMG" >/dev/null || { echo "docker run failed"; exit 2; }
for i in $(seq 1 90); do curl -fsS "http://127.0.0.1:$PORT/health" >/dev/null 2>&1 && { echo "[$LABEL] ready after ${i}s"; break; }; sleep 1; done
echo "[$LABEL] image: $(docker inspect -f '{{.Id}}' "$IMG" | cut -c1-19)  size: $(docker inspect -f '{{.Size}}' "$IMG" | awk '{printf "%.0f MB", $1/1e6}')"
echo "[$LABEL] /model: $(curl -s http://127.0.0.1:$PORT/model | "$PY" -c 'import sys,json; d=json.load(sys.stdin); print(d["model_name"], "thr=%.4f"%d["threshold"], d["layers"])')"
echo "[$LABEL] === course set over HTTP (scored once per candidate) ==="
"$PY" "$ROOT/dataset/tools/grade_http.py" "$SET" "$LABEL" "http://127.0.0.1:$PORT/"; RC=$?
echo "[$LABEL] mem after course set: $(docker exec "$NAME" cat /sys/fs/cgroup/memory.current 2>/dev/null | awk '{printf "%.0f MiB", $1/1048576}') peak: $(docker exec "$NAME" cat /sys/fs/cgroup/memory.peak 2>/dev/null | awk '{printf "%.0f MiB", $1/1048576}')"
echo "[$LABEL] === largest goodware2 files (1 CPU) ==="
"$PY" - "$ROOT" "$PORT" <<'PYEOF'
import sys, json, pathlib, time, urllib.request
root = pathlib.Path(sys.argv[1]); port = sys.argv[2]
idx = [json.loads(l) for l in open(root / "dataset/goodware2/index.jsonl")]
files = sorted(((root / f"dataset/goodware2/pe/{d['sha256']}.bin"), d.get("product")) for d in idx if (root / f"dataset/goodware2/pe/{d['sha256']}.bin").exists())
files = sorted(files, key=lambda t: -t[0].stat().st_size)[:6]
for p, prod in files:
    b = p.read_bytes(); t = time.time()
    try:
        with urllib.request.urlopen(urllib.request.Request(f"http://127.0.0.1:{port}/", data=b, method="POST", headers={"Content-Type": "application/octet-stream"}), timeout=30) as r:
            res = json.loads(r.read()).get("result")
    except Exception as e:
        res = f"ERR {e}"
    print(f"   {len(b)/1e6:6.1f} MB  {time.time()-t:5.2f} s  result={res}  {str(prod)[:40]}")
PYEOF
echo "[$LABEL] mem peak after large files: $(docker exec "$NAME" cat /sys/fs/cgroup/memory.peak 2>/dev/null | awk '{printf "%.0f MiB", $1/1048576}')  oom_kill: $(docker exec "$NAME" sh -c 'grep oom_kill /sys/fs/cgroup/memory.events' 2>/dev/null)"
echo "[$LABEL] memory.stat now (anon = process memory, file = reclaimable page cache): $(docker exec "$NAME" cat /sys/fs/cgroup/memory.stat 2>/dev/null | awk '/^(anon|file|shmem|file_mapped) /{printf "%s=%.0fMiB ", $1, $2/1048576}')"
# peak of anon alone, sampled IN the container every 20 ms (a 0.2 s docker-exec sampler undersampled it)
B=$(ls -S "$ROOT"/dataset/goodware2/pe/*.bin | head -1)
docker exec -d "$NAME" python -c "
import time
mx=0; t_end=time.time()+40
with open('/tmp/anon_max','w') as out:
    while time.time()<t_end:
        for line in open('/sys/fs/cgroup/memory.stat'):
            if line.startswith('anon '):
                v=int(line.split()[1]); mx=max(mx,v); break
        out.seek(0); out.write(str(mx)); out.flush(); time.sleep(0.02)
"
sleep 0.3
for k in 1 2 3; do curl -s -o /dev/null -XPOST --data-binary @"$B" -H 'Content-Type: application/octet-stream' "http://127.0.0.1:$PORT/"; done
sleep 0.5
echo "[$LABEL] anon memory while scoring the largest file 3x (20 ms in-container sampler): max $(docker exec "$NAME" cat /tmp/anon_max 2>/dev/null | awk '{printf "%.0f MiB", $1/1048576}')  idle now: $(docker exec "$NAME" awk '/^anon /{printf "%.0f MiB", $2/1048576}' /sys/fs/cgroup/memory.stat)"
echo "[$LABEL] malformed input -> $(curl -s -XPOST --data-binary 'MZ garbage' -H 'Content-Type: application/octet-stream' http://127.0.0.1:$PORT/)"
docker logs "$NAME" 2>&1 | grep -ci "traceback\|error" | sed "s/^/[$LABEL] error lines in container log: /"
docker rm -f "$NAME" >/dev/null 2>&1
echo "[$LABEL] gate exit code: $RC (wall $(( $(date +%s) - T0 ))s)"
