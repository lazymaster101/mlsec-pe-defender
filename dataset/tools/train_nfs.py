#!/usr/bin/env python3
"""Retrain the NFS pipeline on an NFS-schema dataset and export runtime arrays.

Keeps the supplied model's feature space (22 numeric + one-hot machine/magic +
five hashed text blocks) so a comparison against it isolates the effect of *data*
rather than confounding it with a feature change. scikit-learn is used for fitting
only; the exported arrays are served by the sklearn-free runtime.

Forest size is capped by ``--min-samples-leaf``: fully grown trees on this corpus
produce ~25M nodes, which is larger than the supplied model and wastes the RAM
budget for negligible accuracy.

    python train_nfs.py --train work/ember_official/train.jsonl \
                        --out models/nfs_retrained --max-per-class 100000
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import pathlib
import random
import sys
import time

import numpy as np
from scipy import sparse
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import HashingVectorizer
from sklearn.preprocessing import OneHotEncoder
from sklearn.utils.sparsefuncs import inplace_column_scale

NUMERICAL = [
    "virtual_size", "has_debug", "imports", "exports", "has_relocations",
    "has_resources", "has_signature", "has_tls", "symbols", "timestamp",
    "numberof_sections", "major_image_version", "minor_image_version",
    "major_linker_version", "minor_linker_version", "major_operating_system_version",
    "minor_operating_system_version", "major_subsystem_version",
    "minor_subsystem_version", "sizeof_code", "sizeof_headers", "sizeof_heap_commit",
]
CATEGORICAL = ["machine", "magic"]
TEXTUAL = ["libraries", "functions", "exports_list", "dll_characteristics_list",
           "characteristics_list"]
TOKEN_PATTERN = r"(?<=\s)(.*?)(?=\s)"


def load_rows(path: pathlib.Path, max_per_class: int, seed: int):
    """Reservoir-sample per class so a capped run still spans the whole file."""
    reservoirs: dict[int, list] = {0: [], 1: []}
    counts: collections.Counter = collections.Counter()
    rng = random.Random(seed)
    with path.open() as stream:
        for line in stream:
            row = json.loads(line)
            label = row["label"]
            counts[label] += 1
            if not max_per_class:
                reservoirs[label].append(row)
                continue
            pool = reservoirs[label]
            if len(pool) < max_per_class:
                pool.append(row)
            else:
                j = rng.randrange(counts[label])
                if j < max_per_class:
                    pool[j] = row
    rows = reservoirs[0] + reservoirs[1]
    rng.shuffle(rows)
    print(f"  loaded {len(rows):,} rows (seen {counts[0]:,} benign / {counts[1]:,} malicious)",
          file=sys.stderr)
    return rows


def build_matrix(rows, n_hash: int, encoder: OneHotEncoder | None):
    """Assemble the sparse design matrix exactly as NeedForSpeedModel does."""
    numeric = np.array([[row["attributes"][name] for name in NUMERICAL] for row in rows],
                       dtype=np.float64)
    categories = np.array([[str(row["attributes"][name]) for name in CATEGORICAL]
                           for row in rows], dtype=object)
    if encoder is None:
        encoder = OneHotEncoder(handle_unknown="ignore")
        encoder.fit(categories)
    blocks = [sparse.csr_matrix(numeric), encoder.transform(categories)]
    for attribute in TEXTUAL:
        vectorizer = HashingVectorizer(n_features=n_hash, token_pattern=TOKEN_PATTERN)
        blocks.append(vectorizer.transform([str(row["attributes"][attribute]) for row in rows]))
    return sparse.hstack(blocks).tocsr(), encoder


def export_forest(forest, destination: pathlib.Path) -> dict:
    """Write the flat arrays the runtime memory-maps, same format as the supplied model."""
    trees = forest.estimators_
    states = [tree.tree_.__getstate__() for tree in trees]
    counts = [int(state["node_count"]) for state in states]
    total = sum(counts)
    destination.mkdir(parents=True, exist_ok=True)
    arrays = {name: np.lib.format.open_memmap(destination / f"{name}.npy", mode="w+",
                                              dtype=dtype, shape=(total,))
              for name, dtype in (("children_left", "<i4"), ("children_right", "<i4"),
                                  ("features", "<i4"), ("thresholds", "<f8"),
                                  ("probabilities", "<f8"))}
    roots, offset, leaves = [], 0, 0
    for state, count in zip(states, counts):
        nodes, values = state["nodes"], state["values"]
        left, right = nodes["left_child"], nodes["right_child"]
        is_leaf = left == -1
        chunk = slice(offset, offset + count)
        arrays["children_left"][chunk] = np.where(is_leaf, -1, left + offset)
        arrays["children_right"][chunk] = np.where(is_leaf, -1, right + offset)
        arrays["features"][chunk] = nodes["feature"]
        arrays["thresholds"][chunk] = nodes["threshold"]
        sums = values[:, 0, :].sum(axis=1)
        # Modern sklearn already stores normalised class fractions; older stores counts.
        arrays["probabilities"][chunk] = values[:, 0, 1] / np.where(sums > 0, sums, 1.0)
        roots.append(offset)
        offset += count
        leaves += int(is_leaf.sum())
    for array in arrays.values():
        array.flush()
    arrays.clear()
    np.save(destination / "tree_roots.npy", np.asarray(roots, dtype="<i4"), allow_pickle=False)
    return {"n_trees": len(trees), "n_nodes": total, "n_leaves": leaves,
            "tree_node_counts": counts,
            "tree_max_depths": [int(s["max_depth"]) for s in states]}


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--train", type=pathlib.Path, required=True)
    parser.add_argument("--out", type=pathlib.Path, required=True)
    parser.add_argument("--max-per-class", type=int, default=100000)
    parser.add_argument("--extra-train", type=pathlib.Path,
                        help="JSONL rows always included in full (e.g. recent samples "
                             "that reservoir sampling would otherwise drop)")
    parser.add_argument("--n-hash", type=int, default=50000)
    parser.add_argument("--n-estimators", type=int, default=100)
    parser.add_argument("--min-samples-leaf", type=int, default=2)
    parser.add_argument("--max-features", default="0.05",
                        help="fraction/int/'sqrt'; 'sqrt' is far too small for this "
                             "250k-column space where only 22 columns are dense")
    parser.add_argument("--max-depth", type=int, default=None)
    parser.add_argument("--n-jobs", type=int, default=-1)
    parser.add_argument("--seed", type=int, default=20260919)
    args = parser.parse_args()

    print("loading rows...", file=sys.stderr)
    rows = load_rows(args.train, args.max_per_class, args.seed)
    if args.extra_train:
        extra = [json.loads(l) for l in args.extra_train.open() if l.strip()]
        extra = [r for r in extra if r.get("attributes")]
        rows += extra
        print(f"  + {len(extra):,} extra rows always included from {args.extra_train.name}",
              file=sys.stderr)
    labels = np.array([row["label"] for row in rows], dtype=np.int8)

    print("building design matrix...", file=sys.stderr)
    started = time.time()
    matrix, encoder = build_matrix(rows, args.n_hash, None)
    print(f"  {matrix.shape[0]:,} x {matrix.shape[1]:,}  nnz={matrix.nnz:,} "
          f"({matrix.nnz / matrix.shape[0]:.0f}/row)  {time.time() - started:.0f}s",
          file=sys.stderr)

    # MaxAbsScaler, fitted here rather than imported, then applied as sklearn does
    # for sparse input: multiply by the reciprocal of the per-column max.
    scales = np.asarray(np.abs(matrix).max(axis=0).todense()).ravel()
    scales[scales == 0] = 1.0
    inplace_column_scale(matrix, 1.0 / scales)
    matrix = matrix.astype(np.float32)

    print(f"training RandomForest({args.n_estimators} trees, "
          f"min_samples_leaf={args.min_samples_leaf})...", file=sys.stderr)
    started = time.time()
    try:
        max_features = float(args.max_features)
    except ValueError:
        max_features = args.max_features
    forest = RandomForestClassifier(
        n_estimators=args.n_estimators, min_samples_leaf=args.min_samples_leaf,
        max_features=max_features, max_depth=args.max_depth,
        n_jobs=args.n_jobs, random_state=args.seed)
    forest.fit(matrix, labels)
    train_seconds = time.time() - started
    print(f"  trained in {train_seconds / 60:.1f} min", file=sys.stderr)

    print("exporting arrays...", file=sys.stderr)
    forest_info = export_forest(forest, args.out)
    np.save(args.out / "scales.npy", scales.astype("<f8"), allow_pickle=False)

    categories = [[str(v) for v in values] for values in encoder.categories_]
    n_features = len(NUMERICAL) + sum(map(len, categories)) + len(TEXTUAL) * args.n_hash
    assert n_features == matrix.shape[1], (n_features, matrix.shape[1])
    schema = {
        "format_version": 1,
        "model_name": f"NFS_retrained_EMBER2018_{args.max_per_class or 'all'}",
        "classes": [0, 1], "malicious_class_index": 1,
        "n_features": n_features, **forest_info,
        "numerical_attributes": NUMERICAL,
        "categorical_attributes": CATEGORICAL,
        "categorical_categories": categories,
        "categorical_handle_unknown": "ignore",
        "textual_attributes": TEXTUAL,
        "hashing": {a: {"n_features": args.n_hash, "token_pattern": TOKEN_PATTERN,
                        "norm": "l2", "alternate_sign": True, "binary": False,
                        "lowercase": True, "analyzer": "word", "ngram_range": [1, 1]}
                    for a in TEXTUAL},
        "training": {
            "source": str(args.train), "rows": int(len(rows)),
            "benign": int((labels == 0).sum()), "malicious": int((labels == 1).sum()),
            "n_estimators": args.n_estimators, "min_samples_leaf": args.min_samples_leaf,
            "max_features": args.max_features, "max_depth": args.max_depth, "seed": args.seed,
            "extra_train": str(args.extra_train) if args.extra_train else None,
            "sklearn_version": __import__("sklearn").__version__,
            "train_seconds": round(train_seconds, 1),
        },
        "equivalent_malware_decision": {"rule": "malware_probability > malware_threshold",
                                        "malware_threshold": 0.25},
    }
    (args.out / "schema.json").write_text(json.dumps(schema, indent=2) + "\n")
    files = {}
    for path in sorted(args.out.glob("*.npy")):
        array = np.load(path, mmap_mode="r", allow_pickle=False)
        files[path.name] = {"sha256": sha256(path), "bytes": path.stat().st_size,
                            "dtype": str(array.dtype), "shape": list(array.shape)}
    schema_path = args.out / "schema.json"
    files[schema_path.name] = {"sha256": sha256(schema_path), "bytes": schema_path.stat().st_size}
    (args.out / "manifest.json").write_text(json.dumps({
        "format_version": 1, "files": files,
        "total_artifact_bytes": sum(f["bytes"] for f in files.values()),
        "performance_claims": {"fpr_validated": False, "tpr_validated": False},
    }, indent=2) + "\n")
    total_mb = sum(f["bytes"] for f in files.values()) / 1e6
    print(f"wrote {args.out}: {forest_info['n_nodes']:,} nodes, {total_mb:.0f} MB",
          file=sys.stderr)


if __name__ == "__main__":
    main()
