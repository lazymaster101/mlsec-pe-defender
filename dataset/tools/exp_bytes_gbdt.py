#!/usr/bin/env python3
"""E2: parser-independent byte-level LightGBM (EMBER 2018 + recent live data), scored
with family-grouped / package-grouped out-of-fold (OOF) predictions.

Protocol (Arp et al. 2022 "Dos and Don'ts"; Pendlebury et al. TESSERACT):
  * malware CV folds are grouped by FAMILY  -> every OOF malware score comes from a
    model that never saw that family (the grading set is mostly unseen families);
  * goodware CV folds are grouped by PACKAGE -> no near-duplicate leakage between
    train and test goodware;
  * EMBER 2018 train (600k) is in every fold's training set; EMBER 2018 test (200k,
    later in time) is scored by every fold model as a temporal sanity check;
  * the course grading set is never loaded here.
Writes OOF scores for the stacking/threshold stage: dataset/work/exp/e2_<tag>.npz
"""
from __future__ import annotations
import argparse, json, pathlib, time
import numpy as np
import lightgbm as lgb

ROOT = pathlib.Path(__file__).resolve().parents[2]
C = ROOT / "dataset/work/live_cache"
NB = 617


def tpr_at_fpr(sb, sm, fpr):
    t = np.quantile(sb, 1 - fpr)
    return float((sm > t).mean()), float(t)


def group_folds(groups, k, seed):
    rng = np.random.default_rng(seed)
    uniq = np.array(sorted(set(groups)))
    rng.shuffle(uniq)
    fold_of = {g: i % k for i, g in enumerate(uniq)}
    return np.array([fold_of[g] for g in groups])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", default="base")
    ap.add_argument("--w-recent-mal", type=float, default=10.0)
    ap.add_argument("--w-good", type=float, default=10.0)
    ap.add_argument("--ember-frac", type=float, default=1.0, help="subsample EMBER train for speed")
    ap.add_argument("--rounds", type=int, default=800)
    ap.add_argument("--leaves", type=int, default=64)
    ap.add_argument("--folds", type=int, default=5)
    ap.add_argument("--threads", type=int, default=8)
    args = ap.parse_args()

    em = np.load(ROOT / "dataset/work/ember_bytes/train.npz")
    Xe, ye = em["X"], em["y"].astype(np.float32)
    if args.ember_frac < 1:
        idx = np.random.default_rng(0).random(len(ye)) < args.ember_frac
        Xe, ye = Xe[idx], ye[idx]
    et = np.load(ROOT / "dataset/work/ember_bytes/test.npz")
    Xet, yet = et["X"], et["y"]

    Xm = np.load(C / "X_malware.npy")[:, :NB]
    mm = [json.loads(l) for l in open(C / "meta_malware.jsonl")]
    Xg = np.load(C / "X_goodware.npy")[:, :NB]
    gm = [json.loads(l) for l in open(C / "meta_goodware.jsonl")]
    Xc = np.load(C / "X_course.npy")[:, :NB]

    fm = group_folds([d["group"] for d in mm], args.folds, 1)
    fg = group_folds([d["group"] for d in gm], args.folds, 2)
    params = dict(objective="binary", learning_rate=0.05, num_leaves=args.leaves, min_data_in_leaf=50,
                  feature_fraction=0.5, bagging_fraction=0.8, bagging_freq=1, lambda_l2=1.0,
                  num_threads=args.threads, verbose=-1, seed=7)

    oof_m = np.zeros(len(mm)); oof_g = np.zeros(len(gm))
    et_scores, crs_scores = [], []
    t0 = time.time()
    for k in range(args.folds):
        trm, trg = fm != k, fg != k
        X = np.concatenate([Xe, Xm[trm], Xg[trg]])
        y = np.concatenate([ye, np.ones(trm.sum()), np.zeros(trg.sum())]).astype(np.float32)
        w = np.concatenate([np.ones(len(ye)), np.full(trm.sum(), args.w_recent_mal),
                            np.full(trg.sum(), args.w_good)]).astype(np.float32)
        bst = lgb.train(params, lgb.Dataset(X, y, weight=w, free_raw_data=True), num_boost_round=args.rounds)
        oof_m[fm == k] = bst.predict(Xm[fm == k]); oof_g[fg == k] = bst.predict(Xg[fg == k])
        et_scores.append(bst.predict(Xet)); crs_scores.append(bst.predict(Xc))
        print(f"  fold {k}: train {len(y):,} | {time.time()-t0:.0f}s", flush=True)

    et_mean = np.mean(et_scores, axis=0)
    from sklearn.metrics import roc_auc_score
    print(f"[{args.tag}] EMBER-2018 test AUC={roc_auc_score(yet, et_mean):.4f}  "
          f"TPR@1%FPR={tpr_at_fpr(et_mean[yet==0], et_mean[yet==1], .01)[0]:.3f}")
    is_ms = np.array([d["pe"].get("sig_verify") == "OK" and "O=Microsoft Corporation" in (d["pe"].get("signer_subject") or "") for d in gm])
    is_exe = np.array([not d["pe"].get("is_dll") for d in gm])
    for name, sb in (("all goodware", oof_g), ("non-MS goodware", oof_g[~is_ms]), ("non-MS EXE goodware", oof_g[~is_ms & is_exe])):
        for f in (0.01, 0.005):
            tpr, t = tpr_at_fpr(sb, oof_m, f)
            print(f"   unseen-family TPR @ {f:.1%} FPR on {name:20s}: {tpr:.3f} (thr {t:.4f})")
    print(f"   course goodware scores: {np.round(np.mean(crs_scores, axis=0), 3).tolist()}")
    out = ROOT / "dataset/work/exp"; out.mkdir(parents=True, exist_ok=True)
    np.savez(out / f"e2_{args.tag}.npz", oof_m=oof_m, oof_g=oof_g, fold_m=fm, fold_g=fg,
             course=np.mean(crs_scores, axis=0), args=json.dumps(vars(args)))
    print(f"saved {out / f'e2_{args.tag}.npz'}  ({time.time()-t0:.0f}s)")


if __name__ == "__main__":
    main()
