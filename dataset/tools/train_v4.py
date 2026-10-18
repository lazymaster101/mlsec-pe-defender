#!/usr/bin/env python3
"""Train / evaluate the v4 candidate (dev/v4). Pre-registered protocol:

HOLDOUT  30% of goodware2 PRODUCTS (sha256(group) % 10 < 3) are sealed: never used for
         training, fusion fitting or threshold selection. They are only read by
         `--final-eval`, which compares the frozen v3 with v4 on them once.
DEV POOL every other goodware row (corpus, local, course, goodware2 non-holdout).

Members:  e  = ember_gbdt (unchanged)
          r4 = train_rf_v4.py forest; OOF scores come from its grouped CV folds
               (dataset/work/exp/rf_v4_oof_fold*.json)
          f4 = ember_gbdt + ember_ft_v4, stratum-balanced continued boosting on live
               malware + dev-pool goodware; grouped 5-fold OOF for the fusion fit
Fusion / threshold / CV estimate: identical rules to train_v3.py (log-odds logistic on
OOF scores; FPR <= target on all AND on EXE non-Microsoft goodware; 10x5 CV).
"""
from __future__ import annotations
import argparse, hashlib, json, pathlib, re, sys
import numpy as np
import lightgbm as lgb
from sklearn.linear_model import LogisticRegression

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import exp_finetune_gbdt as FT  # noqa: E402
from exp_fusion import msok, logit  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[2]
C = ROOT / "dataset/work/live_cache"
EXP = ROOT / "dataset/work/exp"
MODELS = ROOT / "defender_product/models"
PARAMS = dict(objective="binary", learning_rate=0.03, num_leaves=31, min_data_in_leaf=20, feature_fraction=0.5,
              bagging_fraction=0.8, bagging_freq=1, lambda_l2=5.0, num_threads=8, verbose=-1, seed=11)
BROKEN = ("BAD_DIGEST", "CERT_NOT_FOUND", "INVALID_SIGNER")


def norm_group(group: str) -> str:
    """Canonical PRODUCT key so one product is one group across corpora and naming schemes:
    'chocolatey:'/'choco:' package ids lose .install/.portable/... suffixes and github
    'owner/repo' keys reduce to the repo; then lowercase alphanumerics only.
    e.g. choco:notepadplusplus.install == github:notepad-plus-plus/notepad-plus-plus.
    Collisions only merge groups (stricter splits), never leak."""
    g = group.lower()
    src, _, name = g.partition(":")
    if src in ("chocolatey", "choco"):
        name = re.sub(r"\.(install|portable|commandline|app|tool|exe)$", "", name)
    elif src == "github":
        name = name.split("/")[-1]
    else:
        return g
    return re.sub(r"[^a-z0-9]", "", name)


def holdout_groups() -> set[str]:
    gs = {json.loads(l)["group"] for l in open(C / "meta_goodware2.jsonl")}
    return {g for g in gs if int(hashlib.sha256(g.encode()).hexdigest(), 16) % 10 < 3}


def load(c):
    return [json.loads(l) for l in open(C / f"meta_{c}.jsonl")], np.load(C / f"X_{c}.npy")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", type=int, default=200)
    ap.add_argument("--target", type=float, default=0.0075)
    ap.add_argument("--write-holdout", action="store_true")
    args = ap.parse_args()
    hold = holdout_groups()
    if args.write_holdout:
        import collect_exe_goodware as CG
        grey = CG.greyware_groups(ROOT / "dataset/goodware2/index.jsonl")
        # Sysinternals products: other versions of the course grading-set goodware. Excluded
        # from training AND holdout so the grading set stays an untouched final check.
        sysint = EXP / "v4_sysinternals_groups.json"
        grey = sorted(set(grey) | (set(json.load(open(sysint))) if sysint.exists() else set()))
        json.dump(sorted(hold), open(EXP / "v4_holdout_groups.json", "w"), indent=0)
        json.dump(grey, open(EXP / "v4_excluded_groups.json", "w"), indent=0)
        print(f"sealed {len(hold)} goodware2 products as holdout; excluded {len(grey)} greyware products: {grey}"); return
    excluded = set(json.load(open(EXP / "v4_excluded_groups.json")))

    mm, Xm = load("malware")
    parts = [load(c) for c in ("goodware", "local", "goodware2")]
    gm = [d for p in parts for d in p[0]]; Xg = np.concatenate([p[1] for p in parts])
    banned = {norm_group(g) for g in hold | excluded}   # incl. older versions of holdout products in other corpora
    keep = np.array([norm_group(d["group"]) not in banned for d in gm])
    gm = [d for d, k in zip(gm, keep) if k]; Xg = Xg[keep]
    cm, Xc = load("course")
    print(f"dev pool: malware {len(mm)} | goodware {len(gm)} ({sum(not d['pe'].get('is_dll') for d in gm)} EXE) | "
          f"holdout products sealed: {len(hold)}")
    base = lgb.Booster(model_file=str(FT.BASE))

    # f4: grouped OOF + final
    fm = FT.group_folds([d["group"] for d in mm], 5, 1); fg = FT.group_folds([norm_group(d["group"]) for d in gm], 5, 2)
    f_m = np.zeros(len(mm)); f_g = np.zeros(len(gm)); f_c = []
    for k in range(5):
        trm, trg = fm != k, fg != k
        wm, wg = FT.balanced_weights(mm, gm, trm, trg, 20.0)
        X = np.concatenate([Xm[trm], Xg[trg]])
        ft = lgb.train(PARAMS, lgb.Dataset(X, np.r_[np.ones(trm.sum()), np.zeros(trg.sum())],
                                           weight=np.r_[wm[trm], wg[trg]], init_score=base.predict(X, raw_score=True)), args.rounds)
        P = lambda Z: 1 / (1 + np.exp(-(base.predict(Z, raw_score=True) + ft.predict(Z, raw_score=True))))
        f_m[fm == k] = P(Xm[fm == k]); f_g[fg == k] = P(Xg[fg == k]); f_c.append(P(Xc))
    wm, wg = FT.balanced_weights(mm, gm, np.ones(len(mm), bool), np.ones(len(gm), bool), 20.0)
    X = np.concatenate([Xm, Xg])
    ft = lgb.train(PARAMS, lgb.Dataset(X, np.r_[np.ones(len(mm)), np.zeros(len(gm))], weight=np.r_[wm, wg],
                                       init_score=base.predict(X, raw_score=True)), args.rounds)
    (MODELS / "ember_ft_v4").mkdir(parents=True, exist_ok=True)
    ft.save_model(str(MODELS / "ember_ft_v4/ember_ft.txt"))

    # r4 OOF from rf CV folds
    r_oof_g, r_rt = {}, {}
    for p in sorted(EXP.glob("rf_v4_oof_fold*.json")):
        d = json.load(open(p))
        r_oof_g.update(d["goodware"])
        for k, v in d["recent_test"].items():
            r_rt.setdefault(k, []).append(v)
    r_rt = {k: float(np.mean(v)) for k, v in r_rt.items()}
    print(f"r4 OOF: {len(r_oof_g)} goodware rows, {len(r_rt)} recent_test malware (from rf CV folds)")

    rt = {json.loads(l)["sha256"] for l in open(ROOT / "dataset/work/recent_test.jsonl") if json.loads(l)["label"] == 1}
    rb = {json.loads(l)["sha256"] for l in open(ROOT / "dataset/work/recent_train.jsonl") if json.loads(l)["label"] == 0}
    dups = set(json.load(open(EXP / "recent_test_nfs_dups.json")))
    for d, v in zip(mm, f_m): d["f"] = float(v)
    for d, v in zip(gm, f_g): d["f"] = float(v)
    mal = [d for d in mm if d["sha256"] in rt and d["sha256"] not in dups and d["sha256"] in r_rt]
    good = [d for d in gm if d["sha256"] not in rb and not msok(d) and d["sha256"] in r_oof_g]
    for d in mal: d["r4"] = r_rt[d["sha256"]]
    for d in good: d["r4"] = r_oof_g[d["sha256"]]
    rows = mal + good; y = np.r_[np.ones(len(mal)), np.zeros(len(good))]
    exe = np.array([not d["pe"].get("is_dll") for d in rows])
    cols = {k: logit(np.array([d[src] for d in rows])) for k, src in (("e", "e"), ("r", "r4"), ("f", "f"))}
    fusion = {"members": {"e": "ember_gbdt", "r": "rf_v4", "f": "ember_gbdt+ember_ft_v4"},
              "logit_clip": 1e-6, "target_fpr": args.target, "models": {}}
    for subset in ("efr", "ef", "r"):
        X = np.c_[tuple(cols[m] for m in subset)]
        clf = LogisticRegression(class_weight="balanced", max_iter=5000).fit(X, y)
        s = clf.decision_function(X)
        t = float(max(np.quantile(s[y == 0], 1 - args.target), np.quantile(s[(y == 0) & exe], 1 - args.target)))
        fusion["models"][subset] = {"order": list(subset), "coef": clf.coef_[0].tolist(), "intercept": float(clf.intercept_[0]),
                                    "threshold": t, "fit_tpr": float((s[y == 1] > t).mean()),
                                    "fit_fpr_all": float((s[y == 0] > t).mean()), "fit_fpr_exe": float((s[(y == 0) & exe] > t).mean())}
        m_ = fusion["models"][subset]
        print(f"[{subset}] coef={np.round(clf.coef_[0], 4).tolist()} t={t:.4f} | fit TPR {m_['fit_tpr']:.3f} FPR all {m_['fit_fpr_all']:.3%} EXE {m_['fit_fpr_exe']:.3%}")
    fusion["fit_set"] = {"malware": len(mal), "goodware": len(good), "goodware_exe": int(exe[y == 0].sum())}
    broken = np.array([any(k in str(d["pe"].get("sig_verify")) for k in BROKEN) for d in rows])
    X = np.c_[cols["e"], cols["r"], cols["f"]]; res = []
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
            res.append((flag[te & (y == 1)].mean(), flag[te & (y == 0)].mean(), flag[te & (y == 0) & exe].mean()))
    r = np.array(res); mu = r.mean(axis=0); sd = r.std(axis=0)
    fusion["cv_estimate"] = {"tpr": mu[0], "fpr_all": mu[1], "fpr_exe": mu[2], "tpr_sd": sd[0], "fpr_exe_sd": sd[2],
                             "protocol": "10x stratified 5-fold, threshold on train folds, holdout products excluded"}
    print(f"CV (10x5): TPR {mu[0]:.3f}±{sd[0]:.3f} | FPR all {mu[1]:.3%} | EXE {mu[2]:.3%}±{sd[2]:.3%}")
    json.dump(fusion, open(MODELS / "fusion_v4.json", "w"), indent=2)
    print("wrote models/ember_ft_v4/ember_ft.txt and models/fusion_v4.json")


if __name__ == "__main__":
    main()
