#!/usr/bin/env bash
# Re-evaluate every stored comparison with the corrected metrics (tie-aware AUC, strict-threshold
# operating point; review 2026-09-21, finding 5). Same rows as the originals: same files, same
# --limit-per-class, same seed. Old files are kept as *.pre-review.json; scores are dumped so the
# numbers can be recomputed later without re-scoring.
set -euo pipefail
cd "$(dirname "$0")/../.."
PY=defender_product/.venv/bin/python; RES=dataset/results; EV=dataset/tools/evaluate_models.py
for f in ember_temporal ember_aug recent_test recent_drift; do [ -f "$RES/$f.pre-review.json" ] || cp "$RES/$f.json" "$RES/$f.pre-review.json"; done
mkdir -p "$RES/scores"
echo "### ember_temporal (25k/class, seed 20260919): supplied, retrained_rf, rf_tuned (+ rf_augmented, rf_adv for completeness)"
$PY -I $EV --model supplied=defender_product/models/nfs retrained_rf=dataset/models/nfs_retrained rf_tuned=dataset/models/nfs_rf_tuned rf_augmented=dataset/models/nfs_rf_augmented rf_adv=dataset/models/nfs_rf_adv \
    --jsonl dataset/work/ember_official/test.jsonl --limit-per-class 25000 --label ember_temporal --out "$RES/ember_temporal.json" --dump-scores "$RES/scores/ember_temporal.npz" 2>&1 | grep -v '^{' | tail -8
echo "### ember_aug (same rows): rf_augmented"
$PY -I $EV --model rf_augmented=dataset/models/nfs_rf_augmented --jsonl dataset/work/ember_official/test.jsonl --limit-per-class 25000 --label ember_aug --out "$RES/ember_aug.json" 2>&1 | grep -v '^{' | tail -3
echo "### recent_test (60 benign / 433 malware): rf_tuned, rf_augmented (+ rf_adv)"
$PY -I $EV --model rf_tuned=dataset/models/nfs_rf_tuned rf_augmented=dataset/models/nfs_rf_augmented rf_adv=dataset/models/nfs_rf_adv --jsonl dataset/work/recent_test.jsonl --limit-per-class 100000 --label recent_test --out "$RES/recent_test.json" --dump-scores "$RES/scores/recent_test.npz" 2>&1 | grep -v '^{' | tail -5
echo "### recent_drift (200 benign / 1455 malware incl. 1 unparseable): supplied, rf_tuned"
$PY -I $EV --model supplied=defender_product/models/nfs rf_tuned=dataset/models/nfs_rf_tuned --jsonl dataset/work/recent.jsonl --limit-per-class 100000 --label recent_drift --out "$RES/recent_drift.json" --dump-scores "$RES/scores/recent_drift.npz" 2>&1 | grep -v '^{' | tail -4
echo "### before/after"
$PY -I - <<'PYEOF'
import json
for f in ("ember_temporal", "ember_aug", "recent_test", "recent_drift"):
    old = json.load(open(f"dataset/results/{f}.pre-review.json"))["models"]; new = json.load(open(f"dataset/results/{f}.json"))["models"]
    print(f"\n{f}")
    print(f"  {'model':13s} {'metric':22s} {'before':>9s} {'after':>9s} {'delta':>8s}")
    for name in old:
        for k in ("roc_auc", "pr_auc", "tpr_at_fpr_0.001", "tpr_at_fpr_0.01", "threshold_at_fpr_0.01", "actual_fpr_0.01"):
            a, b = old[name].get(k), new.get(name, {}).get(k)
            if isinstance(a, (int, float)) and isinstance(b, (int, float)):
                print(f"  {name:13s} {k:22s} {a:9.5f} {b:9.5f} {b-a:+8.5f}")
PYEOF
