#!/usr/bin/env python3
"""Confound-free richer-feature detector.

Training mixes BOTH classes through BOTH extraction pipelines so neither pipeline nor
the managed/native file-type predicts the label:
  - EMBER JSONL  (lief-0.9): 100k benign + 100k malicious   [scale + benchmark power]
  - live corpus  (lief-0.17): ~3.4k benign + ~1k recent malware  [serving pipeline + drift]
Live benign >> live malware, so 'live pipeline' is not a malicious cue.

Calibrated to 1% FPR on HELD-OUT live goodware (serving distribution). Validated with a
native-goodware FPR check (the managed/native type-confound guard).
"""
from __future__ import annotations
import json, pathlib, sys
import numpy as np
import lightgbm as lgb

EMBER = pathlib.Path("dataset/work/ember_v2")
LIVE = pathlib.Path("dataset/work/live_corpus")
OUT = pathlib.Path("dataset/models/ember_v2"); OUT.mkdir(parents=True, exist_ok=True)


def tpr_at(scores, y, fpr):
    o = np.argsort(-scores); l = y[o]
    N = int((y == 0).sum()); P = int((y == 1).sum())
    fp = np.cumsum(l == 0); tp = np.cumsum(l == 1)
    ok = np.where(fp <= fpr * N)[0]
    return float(tp[ok[-1]] / P) if len(ok) else 0.0


def main():
    rng = np.random.default_rng(20260919)
    # EMBER (lief-0.9)
    Xe = np.load(EMBER / "X_train.npy"); ye = np.load(EMBER / "y_train.npy")
    Xet = np.load(EMBER / "X_test.npy"); yet = np.load(EMBER / "y_test.npy")
    # live (lief-0.17)
    Xb = np.load(LIVE / "X_benign.npy"); tb = np.load(LIVE / "benign_types.npy")
    Xmtr = np.load(LIVE / "X_mal_train.npy"); Xmte = np.load(LIVE / "X_mal_test.npy")

    # split live benign 80/20 stratified by type; hold out test benign for calibration+FPR
    idx = np.arange(len(Xb)); rng.shuffle(idx)
    is_native = (tb == "native")
    test_mask = np.zeros(len(Xb), bool)
    for typ in ("native", "managed"):
        ti = idx[(tb[idx] == typ)]
        test_mask[ti[:max(1, int(0.2 * len(ti)))]] = True
    Xb_tr, Xb_te = Xb[~test_mask], Xb[test_mask]
    tb_te = tb[test_mask]
    print(f"live benign: train {len(Xb_tr)}  test {len(Xb_te)} "
          f"({int((tb_te=='native').sum())} native / {int((tb_te=='managed').sum())} managed)", file=sys.stderr)
    print(f"live malware: train {len(Xmtr)}  test {len(Xmte)}", file=sys.stderr)

    X = np.vstack([Xe, Xb_tr, Xmtr])
    y = np.concatenate([ye, np.zeros(len(Xb_tr), np.int8), np.ones(len(Xmtr), np.int8)])
    print(f"training LightGBM on {X.shape} "
          f"({int((y==0).sum())} benign / {int((y==1).sum())} malicious)...", file=sys.stderr)
    params = dict(objective="binary", num_iterations=600, learning_rate=0.05,
                  num_leaves=1024, max_depth=15, min_data_in_leaf=50,
                  feature_fraction=0.5, bagging_fraction=0.9, bagging_freq=1,
                  verbose=-1, n_jobs=-1)
    import time; t0 = time.time()
    booster = lgb.train(params, lgb.Dataset(X, y))
    print(f"  trained in {(time.time()-t0)/60:.1f} min", file=sys.stderr)

    # calibrate 1% FPR on held-out LIVE benign (serving distribution)
    sb = booster.predict(Xb_te)
    thr = float(np.sort(sb)[int(np.ceil(0.99 * len(sb))) - 1])
    # validate
    def det(X, thr): return float((booster.predict(X) > thr).mean()) if len(X) else 0.0
    res = {
        "threshold_live_1pct_fpr": thr,
        "goodware_fpr_all": det(Xb_te, thr),
        "goodware_fpr_native": det(Xb_te[tb_te == "native"], thr),
        "goodware_fpr_managed": det(Xb_te[tb_te == "managed"], thr),
        "recent_malware_detect_heldout": det(Xmte, thr),
        "ember_test_tpr_at_1pct_fpr": tpr_at(booster.predict(Xet), yet, 0.01),
        "ember_test_tpr_at_0.1pct_fpr": tpr_at(booster.predict(Xet), yet, 0.001),
        "n_train": int(y.size), "iterations": params["num_iterations"],
    }
    booster.save_model(str(OUT / "ember_v2.txt"))
    (OUT / "operating_point.json").write_text(json.dumps(res, indent=2) + "\n")
    print("\n=== confound-free richer model (ember_v2) ===")
    print(f"  EMBER-test TPR@1%FPR:   {res['ember_test_tpr_at_1pct_fpr']*100:.1f}%   @0.1%: {res['ember_test_tpr_at_0.1pct_fpr']*100:.1f}%")
    print(f"  recent malware (held-out) detect @ live-1%FPR thr: {res['recent_malware_detect_heldout']*100:.1f}%  (rf_adv ~59%)")
    print(f"  goodware FPR @ that thr: all {res['goodware_fpr_all']*100:.2f}%  |  NATIVE {res['goodware_fpr_native']*100:.2f}%  |  managed {res['goodware_fpr_managed']*100:.2f}%")
    print(f"  -> native FPR near 1% and recent detect high = confound fixed")
    print(f"  saved -> {OUT}")


if __name__ == "__main__":
    main()
