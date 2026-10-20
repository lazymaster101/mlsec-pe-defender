#!/usr/bin/env bash
# rf_v41 = rf_v4 recipe + leak fix (no unfiltered recent_train goodware) + canonical product keys.
set -euo pipefail; cd "$(dirname "$0")/../.."
PY=defender_product/.venv/bin/python; EXP=dataset/work/exp
echo "=== [$(date +%H:%M:%S)] rf_v41 grouped 5-fold CV"
$PY dataset/tools/train_rf_v4.py --tag v41 --cv 5 --holdout $EXP/v4_holdout_groups.json
echo "=== [$(date +%H:%M:%S)] rf_v41 export"
$PY dataset/tools/train_rf_v4.py --tag v41 --export --holdout $EXP/v4_holdout_groups.json --out defender_product/models/rf_v41
echo "=== [$(date +%H:%M:%S)] rf_v41 done"
