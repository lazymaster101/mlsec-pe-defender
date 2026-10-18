#!/usr/bin/env python3
"""Train a gradient-boosted detector on the NFS feature space and export it.

Random forests are a poor fit here: with 250k mostly-zero columns and sklearn's
default max_features='sqrt', only ~4% of split attempts even see one of the 22
dense numeric columns, so trees stop early and under-fit. Boosting evaluates every
feature at every split, which is why EMBER's own reference detector is a GBDT.

Exports to the same flat arrays the runtime memory-maps, tagged
``ensemble="gbdt_logistic"``: leaves hold raw log-odds that are summed, not
averaged. The export is verified against LightGBM's own predictions before it is
written, because a silently wrong flattening would look like a modelling result.

    python train_lightgbm.py --train work/ember_official/train.jsonl \
                             --out models/gbdt --max-per-class 150000
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys
import time

import numpy as np
from scipy import sparse
from sklearn.utils.sparsefuncs import inplace_column_scale

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import train_nfs as base                                    # noqa: E402


def flatten(booster, n_trees: int):
    """Depth-first flatten of LightGBM's nested trees into global index arrays."""
    dump = booster.dump_model()
    trees = dump["tree_info"][:n_trees]
    lefts, rights, feats, thresholds, values = [], [], [], [], []
    roots, depths = [], []

    for info in trees:
        roots.append(len(lefts))
        max_depth = 0

        def walk(node: dict, depth: int) -> int:
            nonlocal max_depth
            max_depth = max(max_depth, depth)
            index = len(lefts)
            lefts.append(-1); rights.append(-1); feats.append(-1)
            thresholds.append(0.0); values.append(0.0)
            if "leaf_value" in node:
                values[index] = float(node["leaf_value"])
                return index
            if node.get("decision_type") != "<=":
                raise ValueError(f"Unsupported split type {node.get('decision_type')!r}")
            feats[index] = int(node["split_feature"])
            thresholds[index] = float(node["threshold"])
            left = walk(node["left_child"], depth + 1)
            right = walk(node["right_child"], depth + 1)
            lefts[index], rights[index] = left, right
            return index

        walk(info["tree_structure"], 0)
        depths.append(max_depth)

    return (np.array(lefts, dtype="<i4"), np.array(rights, dtype="<i4"),
            np.array(feats, dtype="<i4"), np.array(thresholds, dtype="<f8"),
            np.array(values, dtype="<f8"), np.array(roots, dtype="<i4"), depths)


def traverse(rows, left, right, feature, threshold, value, roots) -> np.ndarray:
    """Reference traversal used only to verify the flattening."""
    out = np.zeros(rows.shape[0], dtype=np.float64)
    for i in range(rows.shape[0]):
        row = rows[i]
        total = 0.0
        for root in roots:
            node = int(root)
            while left[node] != -1:
                node = int(left[node]) if row[int(feature[node])] <= threshold[node] \
                    else int(right[node])
            total += float(value[node])
        out[i] = total
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--train", type=pathlib.Path, required=True)
    parser.add_argument("--valid", type=pathlib.Path)
    parser.add_argument("--out", type=pathlib.Path, required=True)
    parser.add_argument("--max-per-class", type=int, default=150000)
    parser.add_argument("--valid-per-class", type=int, default=10000)
    parser.add_argument("--n-hash", type=int, default=50000)
    parser.add_argument("--num-leaves", type=int, default=512)
    parser.add_argument("--n-estimators", type=int, default=1500)
    parser.add_argument("--learning-rate", type=float, default=0.05)
    parser.add_argument("--min-child-samples", type=int, default=20)
    parser.add_argument("--early-stopping", type=int, default=75)
    parser.add_argument("--seed", type=int, default=20260919)
    args = parser.parse_args()

    import lightgbm as lgb

    print("loading rows...", file=sys.stderr)
    rows = base.load_rows(args.train, args.max_per_class, args.seed)
    labels = np.array([r["label"] for r in rows], dtype=np.int8)
    print("building design matrix...", file=sys.stderr)
    started = time.time()
    matrix, encoder = base.build_matrix(rows, args.n_hash, None)
    print(f"  {matrix.shape[0]:,} x {matrix.shape[1]:,} nnz={matrix.nnz:,} "
          f"{time.time() - started:.0f}s", file=sys.stderr)

    scales = np.asarray(np.abs(matrix).max(axis=0).todense()).ravel()
    scales[scales == 0] = 1.0
    inplace_column_scale(matrix, 1.0 / scales)
    matrix = matrix.astype(np.float32)

    valid_sets, valid_matrix, valid_labels = [], None, None
    if args.valid:
        # Held-out months only, so early stopping never peeks at the test period.
        valid_rows = base.load_rows(args.valid, args.valid_per_class, args.seed + 1)
        valid_labels = np.array([r["label"] for r in valid_rows], dtype=np.int8)
        valid_matrix, _ = base.build_matrix(valid_rows, args.n_hash, encoder)
        inplace_column_scale(valid_matrix, 1.0 / scales)
        valid_matrix = valid_matrix.astype(np.float32)

    train_set = lgb.Dataset(matrix, label=labels)
    if valid_matrix is not None:
        valid_sets = [lgb.Dataset(valid_matrix, label=valid_labels, reference=train_set)]

    params = {
        "objective": "binary", "metric": ["auc", "binary_logloss"],
        "num_leaves": args.num_leaves, "learning_rate": args.learning_rate,
        "min_child_samples": args.min_child_samples,
        "feature_fraction": 0.5, "bagging_fraction": 0.8, "bagging_freq": 1,
        "verbosity": -1, "seed": args.seed, "num_threads": 0,
        # Sparse zeros are real values here, not missing data.
        "zero_as_missing": False, "use_missing": False,
    }
    print(f"training LightGBM ({args.n_estimators} rounds, "
          f"{args.num_leaves} leaves)...", file=sys.stderr)
    started = time.time()
    callbacks = [lgb.log_evaluation(100)]
    if valid_sets:
        callbacks.append(lgb.early_stopping(args.early_stopping, verbose=True))
    booster = lgb.train(params, train_set, num_boost_round=args.n_estimators,
                        valid_sets=valid_sets or None, callbacks=callbacks)
    train_seconds = time.time() - started
    best = booster.best_iteration or args.n_estimators
    print(f"  trained in {train_seconds / 60:.1f} min, best iteration {best}",
          file=sys.stderr)

    print("flattening and verifying export...", file=sys.stderr)
    left, right, feature, threshold, value, roots, depths = flatten(booster, best)
    sample = matrix[:200].toarray().astype(np.float32)
    mine = traverse(sample, left, right, feature, threshold, value, roots)
    reference = booster.predict(matrix[:200], raw_score=True, num_iteration=best)
    offset = float(np.median(reference - mine))
    residual = float(np.max(np.abs((mine + offset) - reference)))
    print(f"  base_score={offset:.6g}  max |flattened - lightgbm| = {residual:.3e}",
          file=sys.stderr)
    if residual > 1e-6:
        raise SystemExit(f"Flattened trees disagree with LightGBM by {residual}")

    args.out.mkdir(parents=True, exist_ok=True)
    for name, array in (("children_left", left), ("children_right", right),
                        ("features", feature), ("thresholds", threshold),
                        ("probabilities", value), ("tree_roots", roots)):
        np.save(args.out / f"{name}.npy", array, allow_pickle=False)
    np.save(args.out / "scales.npy", scales.astype("<f8"), allow_pickle=False)

    categories = [[str(v) for v in values_] for values_ in encoder.categories_]
    n_features = len(base.NUMERICAL) + sum(map(len, categories)) + \
        len(base.TEXTUAL) * args.n_hash
    assert n_features == matrix.shape[1]
    schema = {
        "format_version": 1, "ensemble": "gbdt_logistic", "base_score": offset,
        "model_name": f"GBDT_EMBER2018_{args.max_per_class or 'all'}",
        "classes": [0, 1], "malicious_class_index": 1,
        "n_features": n_features, "n_trees": int(len(roots)),
        "n_nodes": int(left.size), "n_leaves": int((left == -1).sum()),
        "tree_max_depths": depths,
        "numerical_attributes": base.NUMERICAL,
        "categorical_attributes": base.CATEGORICAL,
        "categorical_categories": categories,
        "categorical_handle_unknown": "ignore",
        "textual_attributes": base.TEXTUAL,
        "hashing": {a: {"n_features": args.n_hash, "token_pattern": base.TOKEN_PATTERN,
                        "norm": "l2", "alternate_sign": True, "binary": False,
                        "lowercase": True, "analyzer": "word", "ngram_range": [1, 1]}
                    for a in base.TEXTUAL},
        "training": {
            "source": str(args.train), "rows": int(len(rows)),
            "benign": int((labels == 0).sum()), "malicious": int((labels == 1).sum()),
            "best_iteration": int(best), "params": params,
            "lightgbm_version": __import__("lightgbm").__version__,
            "train_seconds": round(train_seconds, 1),
            "export_max_abs_error_vs_lightgbm": residual,
        },
    }
    (args.out / "schema.json").write_text(json.dumps(schema, indent=2) + "\n")
    files = {}
    for path in sorted(args.out.glob("*.npy")):
        array = np.load(path, mmap_mode="r", allow_pickle=False)
        files[path.name] = {"sha256": base.sha256(path), "bytes": path.stat().st_size,
                            "dtype": str(array.dtype), "shape": list(array.shape)}
    (args.out / "manifest.json").write_text(json.dumps({
        "format_version": 1, "files": files,
        "total_artifact_bytes": sum(f["bytes"] for f in files.values()),
    }, indent=2) + "\n")
    total = sum(f["bytes"] for f in files.values()) / 1e6
    print(f"wrote {args.out}: {len(roots)} trees, {left.size:,} nodes, {total:.0f} MB",
          file=sys.stderr)


if __name__ == "__main__":
    main()
