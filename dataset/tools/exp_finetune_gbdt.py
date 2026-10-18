#!/usr/bin/env python3
"""E4: fine-tune the deployed ember_gbdt with live-extracted recent data (continued boosting).

Why this avoids the two shortcuts that sank earlier attempts:
  * extractor shortcut: the base trees were fit on EMBER 2018 only; every NEW tree is
    fit on live (lief-0.17) data from BOTH classes, so "which extractor" carries no label
    information for the new trees.
  * file-type shortcut (Arp et al. sampling bias): our goodware is 93% DLL / 81% .NET,
    our malware 85% EXE. Weights are balanced INSIDE each stratum
    (is_dll x is_dotnet): per stratum, total benign weight == total malware weight, and
    stratum mass follows the malware distribution. File type alone then predicts nothing.

Protocol: family-grouped (malware) / package-grouped (goodware) K-fold OOF, exactly as
exp_bytes_gbdt.py, so results are comparable. The grading set is never loaded.
"""
from __future__ import annotations
import argparse, json, pathlib, time
import numpy as np
import lightgbm as lgb

ROOT = pathlib.Path(__file__).resolve().parents[2]
C = ROOT / "dataset/work/live_cache"
BASE = ROOT / "submission/models/ember_gbdt/ember_gbdt.txt"


def group_folds(groups, k, seed):
    rng = np.random.default_rng(seed)
    uniq = np.array(sorted(set(groups))); rng.shuffle(uniq)
    fold_of = {g: i % k for i, g in enumerate(uniq)}
    return np.array([fold_of[g] for g in groups])


def stratum(d):
    p = d["pe"]
    return (bool(p.get("is_dll")), bool(p.get("is_dotnet")))


def balanced_weights(meta_m, meta_g, mask_m, mask_g, cap=None):
    sm = [stratum(d) for d in meta_m]; sg = [stratum(d) for d in meta_g]
    wm = np.zeros(len(meta_m)); wg = np.zeros(len(meta_g))
    n_mal = mask_m.sum()
    for s in set(sm) | set(sg):
        im = mask_m & np.array([x == s for x in sm]); ig = mask_g & np.array([x == s for x in sg])
        if im.sum() == 0 or ig.sum() == 0:
            # stratum only one class has: keep it at small weight so it can't dominate
            wm[im] = 0.2; wg[ig] = 0.2 * (n_mal / max(1, mask_g.sum()))
            continue
        mass = im.sum() / n_mal            # stratum share of malware
        wm[im] = mass / im.sum(); wg[ig] = mass / ig.sum()
    # rescale so the mean weight over used rows is 1
    used = np.concatenate([wm[mask_m], wg[mask_g]])
    f = 1.0 / used.mean()
    wm *= f; wg *= f
    if cap:
        wm = np.minimum(wm, cap); wg = np.minimum(wg, cap)
    return wm, wg


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", default="ft")
    ap.add_argument("--rounds", type=int, default=200)
    ap.add_argument("--lr", type=float, default=0.03)
    ap.add_argument("--leaves", type=int, default=31)
    ap.add_argument("--min-leaf", type=int, default=20)
    ap.add_argument("--cap", type=float, default=20.0)
    ap.add_argument("--folds", type=int, default=5)
    ap.add_argument("--no-balance", action="store_true")
    args = ap.parse_args()

    Xm = np.load(C / "X_malware.npy"); mm = [json.loads(l) for l in open(C / "meta_malware.jsonl")]
    Xg = np.load(C / "X_goodware.npy"); gm = [json.loads(l) for l in open(C / "meta_goodware.jsonl")]
    Xc = np.load(C / "X_course.npy")
    fm = group_folds([d["group"] for d in mm], args.folds, 1)
    fg = group_folds([d["group"] for d in gm], args.folds, 2)
    params = dict(objective="binary", learning_rate=args.lr, num_leaves=args.leaves, min_data_in_leaf=args.min_leaf,
                  feature_fraction=0.5, bagging_fraction=0.8, bagging_freq=1, lambda_l2=5.0,
                  num_threads=8, verbose=-1, seed=11)
    base = lgb.Booster(model_file=str(BASE))
    oof_m = np.zeros(len(mm)); oof_g = np.zeros(len(gm)); crs = []
    t0 = time.time()
    for k in range(args.folds):
        trm, trg = fm != k, fg != k
        if args.no_balance:
            wm, wg = np.ones(len(mm)), np.full(len(gm), trm.sum() / trg.sum())
        else:
            wm, wg = balanced_weights(mm, gm, trm, trg, args.cap)
        X = np.concatenate([Xm[trm], Xg[trg]]); y = np.concatenate([np.ones(trm.sum()), np.zeros(trg.sum())])
        w = np.concatenate([wm[trm], wg[trg]])
        ds = lgb.Dataset(X, y, weight=w, init_score=base.predict(X, raw_score=True), free_raw_data=False)
        ft = lgb.train(params, ds, num_boost_round=args.rounds)
        # final score = sigmoid(base raw + finetune raw)
        pred = lambda Z: 1 / (1 + np.exp(-(base.predict(Z, raw_score=True) + ft.predict(Z, raw_score=True))))
        oof_m[fm == k] = pred(Xm[fm == k]); oof_g[fg == k] = pred(Xg[fg == k]); crs.append(pred(Xc))
    print(f"[{args.tag}] {args.folds} folds in {time.time()-t0:.0f}s")
    is_ms = np.array([d["pe"].get("sig_verify") == "OK" and "O=Microsoft Corporation" in (d["pe"].get("signer_subject") or "") for d in gm])
    is_exe = np.array([not d["pe"].get("is_dll") for d in gm])
    def tpr(sb, f): return float((oof_m > np.quantile(sb, 1 - f)).mean())
    print(f"   unseen-family TPR @1% FPR | all {tpr(oof_g, .01):.3f} | non-MS {tpr(oof_g[~is_ms], .01):.3f} | "
          f"non-MS EXE {tpr(oof_g[~is_ms & is_exe], .01):.3f} | non-MS DLL {tpr(oof_g[~is_ms & ~is_exe], .01):.3f}")
    print(f"   course goodware: {np.round(np.mean(crs, axis=0), 3).tolist()}")
    out = ROOT / "dataset/work/exp"; out.mkdir(parents=True, exist_ok=True)
    np.savez(out / f"e4_{args.tag}.npz", oof_m=oof_m, oof_g=oof_g, fold_m=fm, fold_g=fg,
             course=np.mean(crs, axis=0), args=json.dumps(vars(args)))


if __name__ == "__main__":
    main()
