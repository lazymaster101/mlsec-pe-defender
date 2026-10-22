#!/usr/bin/env bash
# Package the ensemble defender as a self-contained submission: build context submission_<tag>/
# and mlsec-defender-submission-<tag>.zip, then prove the image builds from the zip alone.
#   usage: dataset/tools/package_submission.sh <tag>      e.g. v33
set -euo pipefail
cd "$(dirname "$0")/../.."
TAG="$1"; P=defender_product; OUT="submission_${TAG}"; ZIP="mlsec-defender-submission-${TAG}.zip"
grep -q "ember_ft_${TAG}" "$P/Dockerfile.ensemble" || { echo "Dockerfile.ensemble does not reference ember_ft_${TAG}"; exit 1; }
rm -rf "$OUT"; mkdir -p "$OUT/defender" "$OUT/models"
cp "$P/Dockerfile.ensemble" "$OUT/Dockerfile"; cp "$P/requirements.ensemble.txt" "$P/LICENSE.upstream" "$OUT/"
for f in __init__.py cmdline.py ember_compat.py ember_features.py ensemble.py ensemble_server.py features.py hashing.py model.py server.py trust.py workers.py; do
  cp "$P/defender/$f" "$OUT/defender/"; done
cp -R "$P/models/rf_adv" "$P/models/ember_gbdt" "$P/models/ember_ft_${TAG}" "$OUT/models/"
cp "$P/models/fusion_${TAG}.json" "$OUT/models/"
printf '*\n!Dockerfile\n!requirements.ensemble.txt\n!defender/\n!defender/**\n!models/\n!models/**\n!LICENSE.upstream\n**/__pycache__\n' > "$OUT/.dockerignore"
sed -i '' -e "s|^# Build:  docker build -f Dockerfile.ensemble -t mlsec-defender:ensemble .|# Build:  docker build -t mlsec-defender:${TAG} .|" \
          -e "s|^# Run:    docker run --rm -m 1g -p 8080:8080 mlsec-defender:ensemble|# Run:    docker run --rm -m 1g -p 8080:8080 mlsec-defender:${TAG}|" "$OUT/Dockerfile"
rm -f "$ZIP"; (cd "$OUT" && zip -q -r "../$ZIP" . -x '*/__pycache__/*' '.DS_Store')
echo "zip: $(du -h "$ZIP" | cut -f1) $(unzip -l "$ZIP" | tail -1)"
unzip -l "$ZIP" | grep -i -E "key|\.bin$|\.exe$|__pycache__|\.pyc" && { echo "UNEXPECTED ENTRY"; exit 1; } || echo "zip entries clean"
B=$(mktemp -d); unzip -q "$ZIP" -d "$B"
docker build -q -t "mlsec-defender:${TAG}-fromzip" "$B" >/dev/null && echo "image mlsec-defender:${TAG}-fromzip built from the zip alone"
docker run --rm --entrypoint sh "mlsec-defender:${TAG}-fromzip" -c "ls /app/defender | wc -l | sed 's/^/ serving modules: /'; ls /app/models | tr '\n' ' '; echo"
# the image must actually SERVE (verification 2026-10-22: a zip once shipped without workers.py and built fine)
PORT=$((19600 + RANDOM % 300)); NAME="fromzip_${TAG}_$$"
docker run -d --rm --name "$NAME" -m 1g --cpus 1 --read-only --tmpfs /tmp -p 127.0.0.1:$PORT:8080 "mlsec-defender:${TAG}-fromzip" >/dev/null
for i in $(seq 1 60); do curl -fsS "http://127.0.0.1:$PORT/health" >/dev/null 2>&1 && break; sleep 1; done
curl -fsS "http://127.0.0.1:$PORT/health" >/dev/null 2>&1 || { docker logs "$NAME" 2>&1 | tail -5; docker rm -f "$NAME" >/dev/null; echo "FROM-ZIP IMAGE DOES NOT SERVE"; exit 1; }
SAMPLE=$(ls ml-cybersecuritiy-course/datasets/samples/pe/*.exe | head -1)
R=$(curl -s -XPOST --data-binary @"$SAMPLE" -H 'Content-Type: application/octet-stream' "http://127.0.0.1:$PORT/")
W=$(curl -s "http://127.0.0.1:$PORT/model" | "$(dirname "$0")/../../defender_product/.venv/bin/python" -c 'import sys,json; d=json.load(sys.stdin); print(d["workers"]["mode"], d["workers"]["live"], d["budget_seconds"])')
docker rm -f "$NAME" >/dev/null
echo "from-zip image serves: $(basename "$SAMPLE") -> $R ; workers: $W"
[ "$R" = '{"result": 0}' ] || { echo "UNEXPECTED VERDICT FROM THE FROM-ZIP IMAGE"; exit 1; }
rm -rf "$B"
