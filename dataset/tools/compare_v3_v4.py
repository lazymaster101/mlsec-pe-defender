#!/usr/bin/env python3
"""Apples-to-apples v3 vs v4: identical rows, identical folds, identical fusion/threshold rule.

Rows (the v4 dev pool; sealed holdout + greyware/Sysinternals excluded):
  malware  = recent_test minus NFS-duplicates of training rows (rf members never trained on them)
  goodware = corpus + local + goodware2-dev, non-Microsoft-trusted, minus rf_adv's 140 training rows
Member scores, all out-of-fold for these rows:
  e        ember_gbdt (EMBER-only; out-of-sample everywhere)
  r3       rf_adv (deployed v3; never trained on these goodware rows or on recent_test)
  r4       rf_v4 grouped-CV OOF (rf_v4_oof_fold*.json)
  f3/f4    fine-tune recipes re-run with the SAME grouped folds: v3 recipe trains on corpus+local
           goodware only (as shipped), v4 recipe on the whole dev pool; scores are OOF
Then for each version: 10x stratified 5-fold fusion CV, threshold on train folds with FPR <=
target on all AND EXE goodware, tamper rule applied. Also reports each version's TPR at matched
held-out EXE FPR. The grading set and the sealed holdout are never loaded.
"""
from __future__ import annotations
import argparse, hashlib, json, pathlib, sys
import numpy as np
import lightgbm as lgb
from sklearn.linear_model import LogisticRegression

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import exp_finetune_gbdt as FT  # noqa: E402
from exp_fusion import msok, logit  # noqa: E402
from train_v4 import PARAMS, BROKEN, norm_group  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[2]
C = ROOT / "dataset/work/live_cache"; EXP = ROOT / "dataset/work/exp"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--v4-tag", default="v4", help="rf OOF files rf_<tag>_oof_fold*.json; output compare_v3_<tag>.json")
    ap.add_argument("--attack-share", type=float, default=0.0, help=">0: f4 recipe is attack-aware with this variant share (train_v41)")
    ap.add_argument("--rounds", type=int, default=200)
    ap.add_argument("--target", type=float, default=0.0075)
    args = ap.parse_args(); target, rounds = args.target, args.rounds
    adv_meta, Xa, orig = [], None, np.zeros(0, int)
    if args.attack_share > 0:
        from train_v41 import variant_weights
        adv_meta = [json.loads(l) for l in open(C / "meta_malware_adv.jsonl")]; Xa = np.load(C / "X_malware_adv.npy")
    banned = {norm_group(g) for g in json.load(open(EXP / "v4_holdout_groups.json")) + json.load(open(EXP / "v4_excluded_groups.json"))}
    L = lambda c: ([json.loads(l) for l in open(C / f"meta_{c}.jsonl")], np.load(C / f"X_{c}.npy"))
    mm, Xm = L("malware")
    rows, Xs = [], []
    for c in ("goodware", "local", "goodware2"):
        m, X = L(c)
        keep = [i for i, d in enumerate(m) if norm_group(d["group"]) not in banned]
        for i in keep:
            m[i]["corpus"] = c
        rows += [m[i] for i in keep]; Xs.append(X[keep])
    gm, Xg = rows, np.concatenate(Xs)
    base = lgb.Booster(model_file=str(FT.BASE))
    fm = FT.group_folds([d["group"] for d in mm], 5, 1); fg = FT.group_folds([norm_group(d["group"]) for d in gm], 5, 2)
    if adv_meta:
        idx = {d["sha256"]: i for i, d in enumerate(mm)}; orig = np.array([idx[m["orig"]] for m in adv_meta]); fa = fm[orig]
    v3_pool = np.array([d["corpus"] in ("goodware", "local") for d in gm])
    oof = {"f3": (np.zeros(len(mm)), np.zeros(len(gm))), "f4": (np.zeros(len(mm)), np.zeros(len(gm)))}
    for k in range(5):
        for name, pool in (("f3", v3_pool), ("f4", np.ones(len(gm), bool))):
            trm = fm != k; trg = (fg != k) & pool
            wm, wg = FT.balanced_weights(mm, gm, trm, trg, 20.0)
            if name == "f4" and adv_meta:            # v4.1 recipe: attack variants in the original's fold
                keep = fa != k
                wm, wv = variant_weights(mm, adv_meta, trm, wm, keep, args.attack_share)
                X = np.concatenate([Xm[trm], Xa[keep], Xg[trg]])
                y_ = np.r_[np.ones(trm.sum() + keep.sum()), np.zeros(trg.sum())]; w_ = np.r_[wm[trm], wv[keep], wg[trg]]
            else:
                X = np.concatenate([Xm[trm], Xg[trg]])
                y_ = np.r_[np.ones(trm.sum()), np.zeros(trg.sum())]; w_ = np.r_[wm[trm], wg[trg]]
            ft = lgb.train(PARAMS, lgb.Dataset(X, y_, weight=w_, init_score=base.predict(X, raw_score=True)), rounds)
            P = lambda Z: 1 / (1 + np.exp(-(base.predict(Z, raw_score=True) + ft.predict(Z, raw_score=True))))
            oof[name][0][fm == k] = P(Xm[fm == k]); oof[name][1][fg == k] = P(Xg[fg == k])
    r4g, r4m = {}, {}
    for p in sorted(EXP.glob(f"rf_{args.v4_tag}_oof_fold*.json")):
        d = json.load(open(p)); r4g.update(d["goodware"])
        for k, v in d["recent_test"].items():
            r4m.setdefault(k, []).append(v)
    rt = {json.loads(l)["sha256"] for l in open(ROOT / "dataset/work/recent_test.jsonl") if json.loads(l)["label"] == 1}
    rb = {json.loads(l)["sha256"] for l in open(ROOT / "dataset/work/recent_train.jsonl") if json.loads(l)["label"] == 0}
    dups = set(json.load(open(EXP / "recent_test_nfs_dups.json")))
    mi = [i for i, d in enumerate(mm) if d["sha256"] in rt and d["sha256"] not in dups and d["sha256"] in r4m]
    gi = [i for i, d in enumerate(gm) if d["sha256"] not in rb and not msok(d) and d["sha256"] in r4g]
    M = [mm[i] for i in mi]; G = [gm[i] for i in gi]
    y = np.r_[np.ones(len(M)), np.zeros(len(G))]
    exe = np.array([not d["pe"].get("is_dll") for d in M + G])
    new = np.array([False] * len(M) + [d["corpus"] == "goodware2" for d in G])
    broken = np.array([any(b in str(d["pe"].get("sig_verify")) for b in BROKEN) for d in M + G])
    e = logit(np.array([d["e"] for d in M + G]))
    r3 = logit(np.array([d["r"] for d in M + G]))
    r4 = logit(np.r_[[np.mean(r4m[d["sha256"]]) for d in M], [r4g[d["sha256"]] for d in G]])
    f3 = logit(np.r_[oof["f3"][0][mi], oof["f3"][1][gi]]); f4 = logit(np.r_[oof["f4"][0][mi], oof["f4"][1][gi]])
    print(f"identical rows: malware {len(M)} | goodware {len(G)} (EXE {int(exe[y == 0].sum())}, of which new goodware2 EXE {int((exe & new).sum())})")
    out = {}
    T4 = args.v4_tag
    for name, X in (("v3 recipe (e, rf_adv, f3)", np.c_[e, r3, f3]), (f"{T4} recipe (e, rf_{T4}, f4)", np.c_[e, r4, f4]),
                    (f"{T4} rf only (e, rf_{T4}, f3)", np.c_[e, r4, f3]), (f"{T4} ft only (e, rf_adv, f4)", np.c_[e, r3, f4])):
        res = []
        for rep in range(10):
            rng = np.random.default_rng(rep); fold = np.empty(len(y), int)
            for c in (0, 1):
                for ex in (False, True):
                    ix = np.where((y == c) & (exe == ex))[0]; rng.shuffle(ix); fold[ix] = np.arange(len(ix)) % 5
            for k in range(5):
                tr, te = fold != k, fold == k
                sc = LogisticRegression(class_weight="balanced", max_iter=5000).fit(X[tr], y[tr]).decision_function(X)
                t = max(np.quantile(sc[tr & (y == 0)], 1 - target), np.quantile(sc[tr & (y == 0) & exe], 1 - target))
                fl = (sc > t) | broken
                # matched operating point: TPR at the held-out-fold EXE-goodware 1% FPR quantile
                tm = np.quantile(sc[te & (y == 0) & exe], 0.99)
                res.append((fl[te & (y == 1)].mean(), fl[te & (y == 0)].mean(), fl[te & (y == 0) & exe].mean(),
                            fl[te & (y == 0) & exe & new].mean(), ((sc > tm) | broken)[te & (y == 1)].mean()))
        r = np.array(res); mu = r.mean(axis=0); sd = r.std(axis=0)
        out[name] = dict(zip(("tpr", "fpr_all", "fpr_exe", "fpr_exe_new", "tpr_at_matched_exe_fpr1"), mu.tolist()))
        print(f"{name:28s} TPR {mu[0]:.3f}±{sd[0]:.3f} | FPR all {mu[1]:.3%} EXE {mu[2]:.3%} (new EXE {mu[3]:.3%}) | TPR @ matched EXE-FPR 1%: {mu[4]:.3f}±{sd[4]:.3f}")
    out["_config"] = vars(args)
    json.dump(out, open(EXP / f"compare_v3_{T4}.json", "w"), indent=2)


if __name__ == "__main__":
    main()
