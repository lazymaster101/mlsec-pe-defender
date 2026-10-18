#!/usr/bin/env python3
"""E6: does a third member (stratum-balanced fine-tune of ember_gbdt on live data, now
with corpus + local goodware) add signal over log-odds fusion of (e, r)?

Step 1: grouped 5-fold OOF fine-tune scores `f` for every malware (family-grouped) and
        goodware row (package/origin-grouped). Course exes are scored by the fold average.
Step 2: fusion CV exactly as exp_fusion.py (malware = recent_test; goodware = non-MS),
        comparing [le, lr] vs [le, lr, lf] at an FPR target applied to all AND EXE goodware.
Grading set never loaded.
"""
from __future__ import annotations
import json, pathlib, sys
import numpy as np
import lightgbm as lgb
from sklearn.linear_model import LogisticRegression

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import exp_finetune_gbdt as FT  # noqa: E402
from exp_fusion import msok, logit  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[2]
C = ROOT / "dataset/work/live_cache"


def main(rounds=200, lr=0.03, leaves=31):
    L = lambda c: [json.loads(l) for l in open(C / f"meta_{c}.jsonl")]
    mm = L("malware"); gm = L("goodware") + L("local"); cm = L("course")
    Xm = np.load(C / "X_malware.npy"); Xg = np.concatenate([np.load(C / "X_goodware.npy"), np.load(C / "X_local.npy")])
    Xc = np.load(C / "X_course.npy")
    fm = FT.group_folds([d["group"] for d in mm], 5, 1); fg = FT.group_folds([d["group"] for d in gm], 5, 2)
    base = lgb.Booster(model_file=str(FT.BASE))
    params = dict(objective="binary", learning_rate=lr, num_leaves=leaves, min_data_in_leaf=20, feature_fraction=0.5,
                  bagging_fraction=0.8, bagging_freq=1, lambda_l2=5.0, num_threads=8, verbose=-1, seed=11)
    fo_m = np.zeros(len(mm)); fo_g = np.zeros(len(gm)); fc = []
    for k in range(5):
        trm, trg = fm != k, fg != k
        wm, wg = FT.balanced_weights(mm, gm, trm, trg, 20.0)
        X = np.concatenate([Xm[trm], Xg[trg]]); y = np.r_[np.ones(trm.sum()), np.zeros(trg.sum())]
        ft = lgb.train(params, lgb.Dataset(X, y, weight=np.r_[wm[trm], wg[trg]], init_score=base.predict(X, raw_score=True)), rounds)
        P = lambda Z: 1 / (1 + np.exp(-(base.predict(Z, raw_score=True) + ft.predict(Z, raw_score=True))))
        fo_m[fm == k] = P(Xm[fm == k]); fo_g[fg == k] = P(Xg[fg == k]); fc.append(P(Xc))
    for d, f in zip(mm, fo_m): d["f"] = float(f)
    for d, f in zip(gm, fo_g): d["f"] = float(f)
    for d, f in zip(cm, np.mean(fc, axis=0)): d["f"] = float(f)

    rt = {json.loads(l)["sha256"] for l in open(ROOT / "dataset/work/recent_test.jsonl") if json.loads(l)["label"] == 1}
    rtrain_b = {json.loads(l)["sha256"] for l in open(ROOT / "dataset/work/recent_train.jsonl") if json.loads(l)["label"] == 0}
    mal = [d for d in mm if d["sha256"] in rt]
    good = [d for d in gm + cm if d["sha256"] not in rtrain_b and not msok(d)]
    y = np.r_[np.ones(len(mal)), np.zeros(len(good))]
    isexe = np.array([not d["pe"].get("is_dll") for d in mal + good])
    rows = mal + good
    le = logit(np.array([d["e"] for d in rows])); lr_ = logit(np.array([d["r"] for d in rows])); lf = logit(np.array([d["f"] for d in rows]))
    print(f"fit set: malware {len(mal)} | non-MS goodware {len(good)} (EXE {int(isexe[y == 0].sum())})")
    for name, X in (("e+r", np.c_[le, lr_]), ("f only", np.c_[lf]), ("e+f", np.c_[le, lf]), ("e+r+f", np.c_[le, lr_, lf])):
        for target in (0.01, 0.0075, 0.005):
            res = []
            for rep in range(5):
                rng = np.random.default_rng(rep); fold = np.empty(len(y), int)
                for cls in (0, 1):
                    for ex in (False, True):
                        ix = np.where((y == cls) & (isexe == ex))[0]; rng.shuffle(ix); fold[ix] = np.arange(len(ix)) % 5
                for k in range(5):
                    tr, te = fold != k, fold == k
                    clf = LogisticRegression(class_weight="balanced", max_iter=2000).fit(X[tr], y[tr]); s = clf.decision_function(X)
                    t = max(np.quantile(s[tr & (y == 0)], 1 - target), np.quantile(s[tr & (y == 0) & isexe], 1 - target))
                    res.append(((s[te & (y == 1)] > t).mean(), (s[te & (y == 0)] > t).mean(), (s[te & (y == 0) & isexe] > t).mean()))
            r = np.mean(res, axis=0)
            print(f"  {name:7s} target {target:.2%}: TPR {r[0]:.3f} | held-out FPR all {r[1]:.3%} EXE {r[2]:.3%}")
    print("course f scores:", [round(d["f"], 3) for d in cm])
    np.savez(ROOT / "dataset/work/exp/e6_oof.npz", fo_m=fo_m, fo_g=fo_g)


if __name__ == "__main__":
    main()
