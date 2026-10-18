#!/usr/bin/env python3
"""Train the deployable EMBER-2381 LightGBM detector: EMBER temporal train (cached
2381 vectors) + recent MalwareBazaar malware (live-extracted), calibrated to 1% FPR.

This is the accuracy+drift core of the 'richer features' upgrade. Serving uses the
same live extractor (ember + ember_compat), so recent-malware training features and
served features come from the same lief-0.17 path (consistent).
"""
from __future__ import annotations
import glob, json, pathlib, sys, time
import numpy as np

sys.path.insert(0, "dataset/tools")
import ember_compat  # noqa: F401  (applies lief-0.17 / numpy-2 patches)
import ember
import lightgbm as lgb
import pyzipper

CACHE = pathlib.Path("dataset/work/ember_v2")
OUT = pathlib.Path("dataset/models/ember_deploy")
EXT = ember.PEFeatureExtractor(2, print_feature_warning=False)


def live_vec(bytez):
    return np.asarray(EXT.feature_vector(bytez), dtype=np.float32)


def load_recent_malware_bytes(split_jsonl, limit=None):
    """Map recent_train SHAs -> quarantine zips -> decrypted bytes (in memory)."""
    shas = [json.loads(l)["sha256"] for l in open(split_jsonl)
            if json.loads(l).get("label") == 1]
    out = []
    for s in shas:
        z = pathlib.Path(f"dataset/quarantine/archives/{s}.zip")
        if not z.exists():
            continue
        try:
            with pyzipper.AESZipFile(z) as a:
                a.setpassword(b"infected"); out.append(a.read(a.infolist()[0]))
        except Exception:
            pass
        if limit and len(out) >= limit:
            break
    return out


def tpr_at(scores, y, fpr):
    o = np.argsort(-scores); l = y[o]
    N = int((y == 0).sum()); P = int((y == 1).sum())
    fp = np.cumsum(l == 0); tp = np.cumsum(l == 1)
    ok = np.where(fp <= fpr * N)[0]
    return (tp[ok[-1]] / P) if len(ok) else 0.0


def main():
    print("loading cached EMBER train/test vectors...", file=sys.stderr)
    Xtr = np.load(CACHE / "X_train.npy"); ytr = np.load(CACHE / "y_train.npy")
    Xte = np.load(CACHE / "X_test.npy"); yte = np.load(CACHE / "y_test.npy")

    print("live-extracting recent MalwareBazaar malware (EMBER-2381)...", file=sys.stderr)
    t0 = time.time()
    mb = load_recent_malware_bytes("dataset/work/recent_train.jsonl")
    Xmb = np.array([live_vec(b) for b in mb], dtype=np.float32)
    ymb = np.ones(len(Xmb), dtype=np.int8)
    print(f"  {len(Xmb)} recent malware vectors in {(time.time()-t0)/60:.1f} min", file=sys.stderr)

    X = np.vstack([Xtr, Xmb]); y = np.concatenate([ytr, ymb])
    print(f"training LightGBM on {X.shape} ({int((y==0).sum())} benign / {int((y==1).sum())} malicious)...", file=sys.stderr)
    params = dict(objective="binary", num_iterations=750, learning_rate=0.05,
                  num_leaves=2048, max_depth=15, min_data_in_leaf=50,
                  feature_fraction=0.5, bagging_fraction=0.9, bagging_freq=1,
                  verbose=-1, n_jobs=-1)
    t0 = time.time()
    booster = lgb.train(params, lgb.Dataset(X, y))
    print(f"  trained in {(time.time()-t0)/60:.1f} min", file=sys.stderr)

    # calibrate threshold to 1% FPR on cached EMBER test benign
    ste = booster.predict(Xte)
    benign = ste[yte == 0]
    thr = float(np.sort(benign)[int(np.ceil(0.99 * benign.size)) - 1])
    fpr = float((benign > thr).mean())
    m = {"roc_auc": None,
         "tpr_at_1pct_fpr": tpr_at(ste, yte, 0.01),
         "tpr_at_0.1pct_fpr": tpr_at(ste, yte, 0.001),
         "threshold_1pct": thr, "actual_fpr": fpr}
    OUT.mkdir(parents=True, exist_ok=True)
    booster.save_model(str(OUT / "ember_deploy.txt"))
    (OUT / "operating_point.json").write_text(json.dumps({
        "feature_space": "EMBER-2381", "threshold": thr, "fpr": fpr,
        "n_train": int(y.size), "n_recent_malware": int(len(Xmb)),
        "iterations": params["num_iterations"], **m}, indent=2) + "\n")
    print("\n=== deployable EMBER-2381 model ===")
    print(f"  EMBER temporal test: TPR@1%FPR {m['tpr_at_1pct_fpr']*100:.1f}%  "
          f"TPR@0.1%FPR {m['tpr_at_0.1pct_fpr']*100:.1f}%")
    print(f"  deployed threshold {thr:.4f} (FPR {fpr*100:.2f}% on EMBER benign)")
    print(f"  saved -> {OUT}")


if __name__ == "__main__":
    main()
