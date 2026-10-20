#!/usr/bin/env python3
"""v4.1 = v4 protocol + attack-aware ember_ft (Lucas et al. 2023) + leak-fixed rf_v41.

Differences from train_v4.py:
  * ember_ft_v41 trains on clean live malware AND their in-memory attack variants
    (build_attack_cache.py: overlay_1m, overlay_4m, strings_10k, section_inject), labeled
    malicious. A variant always sits in its original's family fold, so OOF scores for a
    held-out family never saw that family, attacked or not. Within each file-type stratum
    the clean rows and the variant rows carry equal total weight (clean signal is not
    drowned by 4x variants).
  * r member = rf_v41 (recent_train goodware leak removed; canonical product keys).
  * fusion / threshold / CV estimate rules are unchanged (pre-registered).
Same sealed holdout and exclusions as v4. The grading set is never loaded.
"""
from __future__ import annotations
import argparse, json, pathlib, sys
import numpy as np
import lightgbm as lgb
from sklearn.linear_model import LogisticRegression

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import exp_finetune_gbdt as FT  # noqa: E402
from exp_fusion import msok, logit  # noqa: E402
from train_v4 import PARAMS, BROKEN, norm_group, holdout_groups, load, C, EXP, MODELS, ROOT  # noqa: E402


def variant_weights(mm, adv_meta, trm, wm, adv_keep, share=0.5):
    """Per-variant weights: in each stratum the variants get `share` of the stratum's
    malware mass and the clean rows keep 1-share; total malware mass is unchanged."""
    strat = lambda pe: (bool(pe.get("is_dll")), bool(pe.get("is_dotnet")))
    s_clean = np.array([strat(d["pe"]) for d in mm], dtype=object)
    s_var = np.array([(m["is_dll"], m["is_dotnet"]) for m in adv_meta], dtype=object)
    wm = wm.copy(); wv = np.zeros(len(adv_meta))
    for s in set(map(tuple, s_clean[trm])):
        ic = trm & np.array([tuple(x) == s for x in s_clean]); iv = adv_keep & np.array([tuple(x) == s for x in s_var])
        mass = wm[ic].sum()
        if iv.sum() == 0:
            continue
        wm[ic] *= (1 - share); wv[iv] = mass * share / iv.sum()
    return wm, wv


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", type=int, default=200)
    ap.add_argument("--target", type=float, default=0.0075)
    ap.add_argument("--tag", default="v41")
    ap.add_argument("--rf-tag", default="v41", help="rf OOF files rf_<tag>_oof_fold*.json")
    ap.add_argument("--no-attack", action="store_true", help="ablation: v4 recipe with rf_v41 only")
    ap.add_argument("--variant-share", type=float, default=0.5, help="share of per-stratum malware mass given to attack variants")
    args = ap.parse_args()
    hold = holdout_groups(); excluded = set(json.load(open(EXP / "v4_excluded_groups.json")))
    banned = {norm_group(g) for g in hold | excluded}

    mm, Xm = load("malware")
    parts = [load(c) for c in ("goodware", "local", "goodware2")]
    gm = [d for p in parts for d in p[0]]; Xg = np.concatenate([p[1] for p in parts])
    keep = np.array([norm_group(d["group"]) not in banned for d in gm])
    gm = [d for d, k in zip(gm, keep) if k]; Xg = Xg[keep]
    cm, Xc = load("course")
    adv_meta = [json.loads(l) for l in open(C / "meta_malware_adv.jsonl")]; Xa = np.load(C / "X_malware_adv.npy")
    if args.no_attack:
        adv_meta, Xa = [], np.zeros((0, Xm.shape[1]), np.float32)
    idx = {d["sha256"]: i for i, d in enumerate(mm)}
    orig = np.array([idx[m["orig"]] for m in adv_meta], dtype=int)
    print(f"dev pool: malware {len(mm)} (+{len(adv_meta)} attack variants) | goodware {len(gm)} "
          f"({sum(not d['pe'].get('is_dll') for d in gm)} EXE) | holdout sealed {len(hold)}", flush=True)
    base = lgb.Booster(model_file=str(FT.BASE))

    fm = FT.group_folds([d["group"] for d in mm], 5, 1); fg = FT.group_folds([norm_group(d["group"]) for d in gm], 5, 2)
    fa = fm[orig] if len(orig) else np.zeros(0, int)        # variant inherits its original's fold

    def fit(trm, trg, adv_keep):
        wm, wg = FT.balanced_weights(mm, gm, trm, trg, 20.0)
        wm, wv = variant_weights(mm, adv_meta, trm, wm, adv_keep, args.variant_share) if len(adv_meta) else (wm, np.zeros(0))
        X = np.concatenate([Xm[trm], Xa[adv_keep], Xg[trg]])
        y = np.r_[np.ones(trm.sum() + adv_keep.sum()), np.zeros(trg.sum())]
        w = np.r_[wm[trm], wv[adv_keep], wg[trg]]
        ft = lgb.train(PARAMS, lgb.Dataset(X, y, weight=w, init_score=base.predict(X, raw_score=True)), args.rounds)
        return lambda Z: 1 / (1 + np.exp(-(base.predict(Z, raw_score=True) + ft.predict(Z, raw_score=True)))), ft

    f_m = np.zeros(len(mm)); f_g = np.zeros(len(gm)); f_c = []; f_a = np.zeros(len(adv_meta))
    for k in range(5):
        P, _ = fit(fm != k, fg != k, fa != k)
        f_m[fm == k] = P(Xm[fm == k]); f_g[fg == k] = P(Xg[fg == k]); f_c.append(P(Xc))
        if len(adv_meta):
            f_a[fa == k] = P(Xa[fa == k])
        print(f"  ember_ft_{args.tag} fold {k} done", flush=True)
    if len(adv_meta):   # diagnostic: OOF detection of attacked held-out families at a crude 0.5 cut
        for a in sorted({m["attack"] for m in adv_meta}):
            ia = np.array([m["attack"] == a for m in adv_meta])
            print(f"  OOF f>0.5 on {a:15s}: {(f_a[ia] > 0.5).mean():.3f}   (clean: {(f_m > 0.5).mean():.3f})")
    _, ft_final = fit(np.ones(len(mm), bool), np.ones(len(gm), bool), np.ones(len(adv_meta), bool))
    (MODELS / f"ember_ft_{args.tag}").mkdir(parents=True, exist_ok=True)
    ft_final.save_model(str(MODELS / f"ember_ft_{args.tag}/ember_ft.txt"))
    for d, v in zip(mm, f_m): d["f"] = float(v)
    for d, v in zip(gm, f_g): d["f"] = float(v)
    for d, v in zip(cm, np.mean(f_c, axis=0)): d["f"] = float(v)

    r_g, r_m = {}, {}
    for p in sorted(EXP.glob(f"rf_{args.rf_tag}_oof_fold*.json")):
        d = json.load(open(p)); r_g.update(d["goodware"])
        for k_, v in d["recent_test"].items():
            r_m.setdefault(k_, []).append(v)
    r_m = {k_: float(np.mean(v)) for k_, v in r_m.items()}
    print(f"rf_{args.rf_tag} OOF: {len(r_g)} goodware rows, {len(r_m)} recent_test malware", flush=True)

    rt = {json.loads(l)["sha256"] for l in open(ROOT / "dataset/work/recent_test.jsonl") if json.loads(l)["label"] == 1}
    rb = {json.loads(l)["sha256"] for l in open(ROOT / "dataset/work/recent_train.jsonl") if json.loads(l)["label"] == 0}
    dups = set(json.load(open(EXP / "recent_test_nfs_dups.json")))
    mal = [d for d in mm if d["sha256"] in rt and d["sha256"] not in dups and d["sha256"] in r_m]
    good = [d for d in gm if d["sha256"] not in rb and not msok(d) and d["sha256"] in r_g]
    for d in mal: d["r4"] = r_m[d["sha256"]]
    for d in good: d["r4"] = r_g[d["sha256"]]
    rows = mal + good; y = np.r_[np.ones(len(mal)), np.zeros(len(good))]
    exe = np.array([not d["pe"].get("is_dll") for d in rows])
    cols = {k_: logit(np.array([d[src] for d in rows])) for k_, src in (("e", "e"), ("r", "r4"), ("f", "f"))}
    fusion = {"version": args.tag, "members": {"e": "ember_gbdt", "r": f"rf_{args.rf_tag}", "f": f"ember_gbdt+ember_ft_{args.tag}"},
              "attack_aware_ft": not args.no_attack, "variant_share": args.variant_share, "rounds": args.rounds, "logit_clip": 1e-6, "target_fpr": args.target, "models": {}}
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
    broken = np.array([any(k_ in str(d["pe"].get("sig_verify")) for k_ in BROKEN) for d in rows])
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
    json.dump(fusion, open(MODELS / f"fusion_{args.tag}.json", "w"), indent=2)
    print(f"wrote models/ember_ft_{args.tag}/ember_ft.txt and models/fusion_{args.tag}.json")


if __name__ == "__main__":
    main()
