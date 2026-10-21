#!/usr/bin/env python3
"""Train the v3.1 detector ML artifacts: the v3 recipe (train_v3.py) with the number of
continued-boosting rounds chosen by grouped CV on the dev pool (200 -> see --rounds),
written to versioned paths so v3 stays intact. Same fit set, same threshold rule, same
CV protocol; the grading set is never loaded.

Original v3 docstring follows.

Train the v3 detector artifacts (see dataset/docs/V3_DETECTOR.md).

Outputs (into defender_product/models/):
  ember_ft/ember_ft.txt  continued-boosting trees on top of ember_gbdt, fit on live
                         (lief-0.17) recent malware + live goodware (corpus + local),
                         with per-(DLL x .NET) stratum class balancing.
  fusion.json            log-odds logistic fusion fitted on OUT-OF-FOLD member scores,
                         one model per member subset for graceful degradation:
                         'efr' (all), 'ef' (NFS failed), 'r' (EMBER failed), + threshold.

Fusion fit set (every member honestly out-of-sample):
  malware  = recent_test (433; never in rf_adv training; ember_gbdt is EMBER-only;
             f is family-grouped OOF)
  goodware = corpus + local + course, minus rf_adv's 140 training rows, minus
             Microsoft-trusted files (the trust layer handles those before fusion).
Threshold rule: the largest-TPR threshold with FPR <= --target on BOTH all fit
goodware and the EXE stratum (Arp et al. P1: per-stratum, strictest wins).
The grading set is never loaded.
"""
from __future__ import annotations
import argparse, json, pathlib, sys
import numpy as np
import lightgbm as lgb
from sklearn.linear_model import LogisticRegression

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import exp_finetune_gbdt as FT  # noqa: E402
from exp_fusion import msok, logit  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[2]
C = ROOT / "dataset/work/live_cache"
OUT = ROOT / "defender_product/models"
PARAMS = dict(objective="binary", learning_rate=0.03, num_leaves=31, min_data_in_leaf=20, feature_fraction=0.5,
              bagging_fraction=0.8, bagging_freq=1, lambda_l2=5.0, num_threads=8, verbose=-1, seed=11)


def finetune(base, X, y, w, rounds):
    return lgb.train(PARAMS, lgb.Dataset(X, y, weight=w, init_score=base.predict(X, raw_score=True)), rounds)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", type=int, default=800)
    ap.add_argument("--tag", default="v31", help="artifact suffix: models/ember_ft_<tag>/, models/fusion_<tag>.json")
    ap.add_argument("--near-dup-l2", type=float, default=0.0,
                    help="v3.3: drop training malware whose EMBER vector is within this L2 of any course malware "
                         "sample (near-identical builds), and drop the course manifest's removed_sha256 hashes; 0 = off")
    ap.add_argument("--target", type=float, default=0.0075)
    args = ap.parse_args()
    L = lambda c: [json.loads(l) for l in open(C / f"meta_{c}.jsonl")]
    mm = L("malware"); gm = L("goodware") + L("local"); cm = L("course")
    Xm = np.load(C / "X_malware.npy"); Xg = np.concatenate([np.load(C / "X_goodware.npy"), np.load(C / "X_local.npy")])
    Xc = np.load(C / "X_course.npy")
    # v3.2 hygiene for feed-collected rows (collect_mb_recent.py):
    #  * rows the extractor could not vectorize are dropped (no NaN rows into LightGBM);
    #  * malware without a family tag is grouped by import hash (near-duplicate proxy), never
    #    pooled into one giant "untagged" group, so family-grouped folds stay meaningful;
    #  * any row whose EMBER vector is identical to a course grading-set sample is dropped
    #    (exact-hash collisions are already refused at collection time). The grading features
    #    are read ONLY to exclude rows; nothing is fitted or calibrated on them.
    keep = ~np.isnan(Xm).any(axis=1)
    for d in mm:
        if d.get("group") in ("untagged", "unknown", None, ""):
            d["group"] = "untagged:" + (d.get("imphash") or d["sha256"][:12])
    gp = C / "X_grading.npy"
    if gp.exists():
        Xgr = np.load(gp); gmeta = L("grading")
        Xgr = Xgr[[str(d.get("label")) == "1" for d in gmeta]]
        Xgr = Xgr[~np.isnan(Xgr).any(axis=1)]
        dup = np.zeros(len(mm), bool)
        for i in np.where(keep)[0]:
            if np.any(np.all(np.isclose(Xgr, Xm[i], rtol=0, atol=1e-6), axis=1)):
                dup[i] = True
        print(f"feature-identical to a grading malware sample: {int(dup.sum())} training rows dropped")
        keep &= ~dup
        if args.near_dup_l2 > 0:
            # review 2026-10-20: isclose(atol=1e-6) cannot see near-identical BUILDS at EMBER scale
            # (per-feature max ~4e9). Exact per-pair L2 (no Gram trick: it is numerically unstable here).
            Xd = Xm.astype(np.float64); dmin = np.full(len(mm), np.inf)
            for g in Xgr.astype(np.float64):
                dmin = np.minimum(dmin, np.linalg.norm(Xd - g, axis=1))
            nd = keep & (dmin < args.near_dup_l2)
            fams = {}
            for i in np.where(nd)[0]:
                fams[mm[i]["group"]] = fams.get(mm[i]["group"], 0) + 1
            print(f"near-duplicate (L2 < {args.near_dup_l2:g}) of a grading malware sample: {int(nd.sum())} rows dropped {fams}")
            keep &= ~nd
            man = json.load(open(ROOT / "csce704-blackbox-validation-100-samples-20261014-corrected/manifest.json"))
            removed = set(man.get("lineage", {}).get("removed_sha256", []))
            rm = keep & np.array([d["sha256"] in removed for d in mm])
            print(f"hashes from the ORIGINAL course release (manifest.lineage.removed_sha256): {int(rm.sum())} rows dropped")
            keep &= ~rm
    print(f"malware rows: {len(mm)} -> {int(keep.sum())} after hygiene; untagged groups: "
          f"{len({d['group'] for d in mm if d['group'].startswith('untagged:')})}")
    mm = [d for d, k in zip(mm, keep) if k]; Xm = Xm[keep]
    base = lgb.Booster(model_file=str(FT.BASE))

    # 1) grouped OOF f for the fusion fit
    fm = FT.group_folds([d["group"] for d in mm], 5, 1); fg = FT.group_folds([d["group"] for d in gm], 5, 2)
    f_m = np.zeros(len(mm)); f_g = np.zeros(len(gm)); f_c = []
    for k in range(5):
        trm, trg = fm != k, fg != k
        wm, wg = FT.balanced_weights(mm, gm, trm, trg, 20.0)
        ft = finetune(base, np.concatenate([Xm[trm], Xg[trg]]), np.r_[np.ones(trm.sum()), np.zeros(trg.sum())],
                      np.r_[wm[trm], wg[trg]], args.rounds)
        P = lambda Z: 1 / (1 + np.exp(-(base.predict(Z, raw_score=True) + ft.predict(Z, raw_score=True))))
        f_m[fm == k] = P(Xm[fm == k]); f_g[fg == k] = P(Xg[fg == k]); f_c.append(P(Xc))
    for d, v in zip(mm, f_m): d["f"] = float(v)
    for d, v in zip(gm, f_g): d["f"] = float(v)
    for d, v in zip(cm, np.mean(f_c, axis=0)): d["f"] = float(v)

    # 2) final f on all data
    wm, wg = FT.balanced_weights(mm, gm, np.ones(len(mm), bool), np.ones(len(gm), bool), 20.0)
    ft = finetune(base, np.concatenate([Xm, Xg]), np.r_[np.ones(len(mm)), np.zeros(len(gm))], np.r_[wm, wg], args.rounds)
    (OUT / f"ember_ft_{args.tag}").mkdir(parents=True, exist_ok=True)
    ft.save_model(str(OUT / f"ember_ft_{args.tag}/ember_ft.txt"))

    # 3) fusion fits on honest rows
    rt = {json.loads(l)["sha256"] for l in open(ROOT / "dataset/work/recent_test.jsonl") if json.loads(l)["label"] == 1}
    rb = {json.loads(l)["sha256"] for l in open(ROOT / "dataset/work/recent_train.jsonl") if json.loads(l)["label"] == 0}
    # drop recent_test rows whose NFS features are identical to an rf_adv training row
    # (84/433): rf_adv is effectively in-sample on them, which would inflate its weight.
    dups = set(json.load(open(ROOT / "dataset/work/exp/recent_test_nfs_dups.json")))
    mal = [d for d in mm if d["sha256"] in rt and d["sha256"] not in dups]
    good = [d for d in gm + cm if d["sha256"] not in rb and not msok(d)]
    rows = mal + good
    y = np.r_[np.ones(len(mal)), np.zeros(len(good))]
    exe = np.array([not d["pe"].get("is_dll") for d in rows])
    cols = {"e": logit(np.array([d["e"] for d in rows])), "r": logit(np.array([d["r"] for d in rows])),
            "f": logit(np.array([d["f"] for d in rows]))}
    fusion = {"version": args.tag, "members": {"e": "ember_gbdt", "r": "rf_adv", "f": f"ember_gbdt+ember_ft_{args.tag}"},
              "ft_rounds": args.rounds, "malware_rows": len(mm), "logit_clip": 1e-6, "target_fpr": args.target, "models": {}}
    for subset in ("efr", "ef", "r"):
        X = np.c_[tuple(cols[m] for m in subset)]
        clf = LogisticRegression(class_weight="balanced", max_iter=5000).fit(X, y)
        s = clf.decision_function(X)
        t = float(max(np.quantile(s[y == 0], 1 - args.target), np.quantile(s[(y == 0) & exe], 1 - args.target)))
        tpr = float((s[y == 1] > t).mean())
        fusion["models"][subset] = {"order": list(subset), "coef": clf.coef_[0].tolist(),
                                    "intercept": float(clf.intercept_[0]), "threshold": t,
                                    "fit_tpr": tpr, "fit_fpr_all": float((s[y == 0] > t).mean()),
                                    "fit_fpr_exe": float((s[(y == 0) & exe] > t).mean())}
        print(f"[{subset}] coef={np.round(clf.coef_[0], 4).tolist()} b={clf.intercept_[0]:.4f} t={t:.4f} | "
              f"fit TPR {tpr:.3f} FPR all {fusion['models'][subset]['fit_fpr_all']:.3%} EXE {fusion['models'][subset]['fit_fpr_exe']:.3%}")
    fusion["fit_set"] = {"malware": len(mal), "goodware": len(good), "goodware_exe": int(exe[y == 0].sum())}

    # 4) honest estimate: repeated stratified 5-fold CV of fusion + threshold rule,
    #    with the tamper rule applied (malware rows carry it; no goodware does).
    broken = np.array([any(k in str(d["pe"].get("sig_verify")) for k in ("BAD_DIGEST", "CERT_NOT_FOUND", "INVALID_SIGNER"))
                       for d in rows])
    X = np.c_[cols["e"], cols["r"], cols["f"]]
    res = []
    for rep in range(10):
        rng = np.random.default_rng(rep); fold = np.empty(len(y), int)
        for c in (0, 1):
            for ex in (False, True):
                ix = np.where((y == c) & (exe == ex))[0]; rng.shuffle(ix); fold[ix] = np.arange(len(ix)) % 5
        for k in range(5):
            tr, te = fold != k, fold == k
            sc = LogisticRegression(class_weight="balanced", max_iter=5000).fit(X[tr], y[tr]).decision_function(X)
            t = max(np.quantile(sc[tr & (y == 0)], 1 - args.target), np.quantile(sc[tr & (y == 0) & exe], 1 - args.target))
            flag = (sc > t) | broken
            res.append((flag[te & (y == 1)].mean(), flag[te & (y == 1) & exe].mean(),
                        flag[te & (y == 0)].mean(), flag[te & (y == 0) & exe].mean()))
    r = np.array(res); m = r.mean(axis=0); sd = r.std(axis=0)
    fusion["cv_estimate"] = {"tpr": m[0], "tpr_exe": m[1], "fpr_all": m[2], "fpr_exe": m[3],
                             "tpr_sd": sd[0], "fpr_exe_sd": sd[3], "protocol": "10x stratified 5-fold, threshold on train folds"}
    print(f"CV (10x5, dedup'd): TPR {m[0]:.3f}±{sd[0]:.3f} (EXE malware {m[1]:.3f}) | FPR all {m[2]:.3%} EXE {m[3]:.3%}±{sd[3]:.3%}")
    json.dump(fusion, open(OUT / f"fusion_{args.tag}.json", "w"), indent=2)
    print("course f (fold-avg):", [round(d["f"], 3) for d in cm])
    p = OUT / f"ember_ft_{args.tag}/ember_ft.txt"; print(f"wrote {p} ({p.stat().st_size/1e6:.1f} MB) and {OUT / f'fusion_{args.tag}.json'}")


if __name__ == "__main__":
    main()
