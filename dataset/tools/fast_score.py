#!/usr/bin/env python3
"""Batch vectorize + batch forest traversal for an exported NFS model.

Reproduces ``Model.vectorize`` / ``Model.probability`` exactly, but over many rows at
once, so evaluation sweeps are seconds instead of minutes. Verified against the
per-row path in this module's __main__.
"""
from __future__ import annotations
import numpy as np
from scipy import sparse
from sklearn.feature_extraction.text import HashingVectorizer


def build_scaled_matrix(model, rows) -> sparse.csr_matrix:
    """Same columns, order and scaling as Model.vectorize, for a list of rows."""
    attrs = [r["attributes"] for r in rows]
    numeric = np.array([[float(a[n]) for n in model._numerical] for a in attrs],
                       dtype=np.float64)
    blocks = [sparse.csr_matrix(numeric)]
    # categorical one-hot, using the model's own category ordering
    for col, catname in enumerate(model._categorical):
        cats = model.schema["categorical_categories"][col]
        index = {v: i for i, v in enumerate(cats)}
        rows_i, cols_i = [], []
        for i, a in enumerate(attrs):
            j = index.get(str(a[catname]))
            if j is not None:
                rows_i.append(i); cols_i.append(j)
        blocks.append(sparse.csr_matrix((np.ones(len(rows_i)), (rows_i, cols_i)),
                                        shape=(len(attrs), len(cats))))
    # hashed text blocks (sklearn HashingVectorizer == the runtime's hashing)
    for attribute, width, _ in model._text_offsets:
        params = model._hashing[attribute]
        hv = HashingVectorizer(n_features=width,
                               token_pattern=params["token_pattern"],
                               norm=params.get("norm", "l2"),
                               alternate_sign=params.get("alternate_sign", True),
                               lowercase=params.get("lowercase", True))
        blocks.append(hv.transform([str(a[attribute]) for a in attrs]))
    X = sparse.hstack(blocks).tocsr()
    assert X.shape[1] == model.n_features, (X.shape[1], model.n_features)
    X = X.multiply(model._inverse_scale).tocsr()      # per-column MaxAbs scaling
    return X.astype(np.float32)


def score_matrix(model, X: sparse.csr_matrix) -> np.ndarray:
    """Forest probabilities for every row of X (forest_mean ensemble)."""
    X = X.tocsr()
    left, right = np.asarray(model._left), np.asarray(model._right)
    feature, threshold = np.asarray(model._feature), np.asarray(model._threshold)
    prob = np.asarray(model._probability)
    n = X.shape[0]
    total = np.zeros(n, dtype=np.float64)
    for root in model._roots:
        nodes = np.full(n, int(root), dtype=np.int64)
        active = left[nodes] != -1
        while active.any():
            idx = np.nonzero(active)[0]
            cur = nodes[idx]
            vals = np.asarray(X[idx, feature[cur]]).ravel()
            go_left = vals <= threshold[cur]
            nodes[idx] = np.where(go_left, left[cur], right[cur])
            active = left[nodes] != -1
        total += prob[nodes]
    return total / len(model._roots)


def score_rows(model, rows) -> np.ndarray:
    return score_matrix(model, build_scaled_matrix(model, rows))


if __name__ == "__main__":
    import json, pathlib, sys
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "defender_product"))
    from defender.model import Model
    root = pathlib.Path(__file__).resolve().parents[1]
    model = Model(root / "models/nfs_rf_augmented", "training")
    rows = [json.loads(l) for l in (root / "work/recent.jsonl").open()][:200]
    rows = [r for r in rows if isinstance(r.get("attributes"), dict)]
    fast = score_rows(model, rows)
    slow = np.array([model.probability(model.vectorize(r["attributes"])) for r in rows])
    print(f"n={len(rows)} max|fast-slow|={np.abs(fast-slow).max():.2e} "
          f"decisions differ={(( fast>0.5)!=(slow>0.5)).sum()}")
