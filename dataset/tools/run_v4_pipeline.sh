#!/usr/bin/env bash
# v4 training pipeline (dev/v4). Resumable: finished rf CV folds are skipped.
# Order matters: the holdout is sealed BEFORE any v4 model sees goodware2.
set -euo pipefail
cd "$(dirname "$0")/../.."
PY=${PY:-defender_product/.venv/bin/python}
EXP=dataset/work/exp
step() { echo "=== [$(date +%H:%M:%S)] $*"; }

step "1/5 live features for goodware2"
$PY dataset/tools/build_live_cache.py --corpora goodware2 --workers 8

step "2/5 seal holdout products + greyware exclusions"
$PY dataset/tools/train_v4.py --write-holdout

step "3/5 rf_v4 grouped 5-fold CV (OOF scores)"
$PY dataset/tools/train_rf_v4.py --cv 5 --holdout $EXP/v4_holdout_groups.json

step "4/5 rf_v4 final export"
$PY dataset/tools/train_rf_v4.py --export --holdout $EXP/v4_holdout_groups.json --out defender_product/models/rf_v4

step "5/5 ember_ft_v4 + fusion_v4 (+ grouped CV estimate)"
$PY dataset/tools/train_v4.py

step "done"
