#!/usr/bin/env python3
"""Install a trained model into the defender_product image and pick its threshold.

Copies the exported arrays into ``defender_product/models/<name>`` and computes the
operating threshold that meets a target FPR on a held-out set, so the deployed
DF_MALWARE_THRESHOLD is measured rather than guessed. It does not overwrite the
supplied model unless asked; the runtime selects a model by DF_MODEL_DIR.

    python package_model.py --model dataset/models/gbdt --name gbdt \
        --calibrate dataset/work/ember_official/test.jsonl --target-fpr 0.01
"""
from __future__ import annotations

import argparse
import json
import pathlib
import shutil
import sys

import numpy as np

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "defender_product"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from defender.model import Model                 # noqa: E402
import evaluate_models as E                       # noqa: E402


def choose_threshold(model: Model, rows: list[dict], target_fpr: float) -> dict:
    scores, _, _ = E.score_rows(model, rows)
    labels = np.array([r["label"] for r in rows], dtype=np.int8)
    benign, malicious = scores[labels == 0], scores[labels == 1]
    # Lowest threshold whose benign exceedance is still within budget: that
    # maximises TPR while holding FPR <= target. Candidates are the distinct
    # benign scores (the only points where FPR changes), scanned ascending.
    best = {"threshold": 1.0, "fpr": 0.0, "tpr": 0.0, "target_fpr": target_fpr,
            "n_benign": int(benign.size), "n_malicious": int(malicious.size)}
    for cut in np.unique(benign):
        fpr = float((benign > cut).mean())
        if fpr <= target_fpr:
            best.update(threshold=float(cut), fpr=fpr,
                        tpr=float((malicious > cut).mean()))
            break
    return best


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--model", type=pathlib.Path, required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--calibrate", type=pathlib.Path)
    parser.add_argument("--calibrate-limit", type=int, default=40000)
    parser.add_argument("--target-fpr", type=float, default=0.01)
    parser.add_argument("--dest", type=pathlib.Path,
                        default=pathlib.Path(__file__).resolve().parents[2]
                        / "defender_product" / "models")
    parser.add_argument("--seed", type=int, default=20260919)
    args = parser.parse_args()

    destination = args.dest / args.name
    destination.mkdir(parents=True, exist_ok=True)
    for path in sorted(args.model.glob("*.npy")):
        shutil.copy2(path, destination / path.name)
    for name in ("schema.json", "manifest.json"):
        source = args.model / name
        if source.exists():
            shutil.copy2(source, destination / name)
    print(f"installed {args.name} -> {destination}", file=sys.stderr)

    if args.calibrate:
        model = Model(destination, "training")
        rows = E.load_jsonl(args.calibrate, args.calibrate_limit, args.seed)
        result = choose_threshold(model, rows, args.target_fpr)
        (destination / "operating_point.json").write_text(json.dumps({
            "calibrated_on": str(args.calibrate), **result}, indent=2) + "\n")
        print(json.dumps(result, indent=2))
        print(f"\nRun with: DF_MODEL_DIR=models/{args.name} "
              f"DF_MALWARE_THRESHOLD={result['threshold']:.6f}", file=sys.stderr)


if __name__ == "__main__":
    main()
