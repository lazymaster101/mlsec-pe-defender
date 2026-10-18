#!/bin/bash
# Full comparison pipeline: calibrate, evaluate on the temporal test set and on
# the recent drift set, for every trained model. Safe to re-run.
set -euo pipefail
cd "/Users/seshadithyasaravanan/Desktop/CSCE 704/Model"
PY="defender_product/.venv/bin/python"
RES="dataset/results"; mkdir -p "$RES"

echo "### 1. Refresh recent drift set from collected samples"
$PY dataset/tools/extract_pe.py --malware dataset/quarantine --goodware dataset/goodware \
    --out dataset/work/recent.jsonl 2>&1 | tail -3

MODELS=(supplied=defender_product/models/nfs retrained_rf=dataset/models/nfs_retrained)
[ -d dataset/models/gbdt ] && MODELS+=(gbdt=dataset/models/gbdt)

echo "### 2. Primary comparison: EMBER 2018 temporal test (2018-11/12, held out)"
$PY dataset/tools/evaluate_models.py --model "${MODELS[@]}" \
    --jsonl dataset/work/ember_official/test.jsonl --limit-per-class 30000 \
    --label ember_temporal --out "$RES/ember_temporal.json" 2>&1 | tail -4

echo "### 3. Drift comparison: recent MalwareBazaar malware + Chocolatey goodware"
$PY dataset/tools/evaluate_models.py --model "${MODELS[@]}" \
    --jsonl dataset/work/recent.jsonl --limit-per-class 100000 \
    --label recent_drift --out "$RES/recent_drift.json" 2>&1 | tail -4

echo "### 4. Calibrate the GBDT operating point at 1% FPR on the temporal test"
if [ -d dataset/models/gbdt ]; then
  $PY dataset/tools/package_model.py --model dataset/models/gbdt --name gbdt \
      --calibrate dataset/work/ember_official/test.jsonl --target-fpr 0.01 2>&1 | tail -6
fi
echo "### DONE; results in $RES/"
