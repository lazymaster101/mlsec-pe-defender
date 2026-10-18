#!/usr/bin/env python3
"""E5: how should ember_gbdt (e) and rf_adv (r) be fused?

Fit rows where BOTH members are honestly out-of-sample:
  malware  = recent_test (433; rf_adv never trained on them; ember_gbdt is EMBER-only)
  goodware = corpus (minus the 140 Chocolatey rows rf_adv trained on) + local + course
Microsoft-trusted goodware is removed first (trust layer returns benign before fusion).

Each candidate is scored by repeated stratified 5-fold CV: fit on 4 folds, pick the
threshold on the TRAINING folds so that FPR <= target on (a) all goodware and (b) EXE
goodware separately (whichever is stricter), then measure TPR/FPR on the held-out fold.
The grading set is never loaded.
"""
from __future__ import annotations
import json, pathlib
import numpy as np
from sklearn.linear_model import LogisticRegression

ROOT = pathlib.Path(__file__).resolve().parents[2]
C = ROOT / "dataset/work/live_cache"
L = lambda c: [json.loads(l) for l in open(C / f"meta_{c}.jsonl")]


def msok(d):
    return d["pe"].get("sig_verify") == "OK" and "O=Microsoft Corporation" in (d["pe"].get("signer_subject") or "")


def logit(p):
    p = np.clip(p, 1e-6, 1 - 1e-6)
    return np.log(p / (1 - p))


def feats(rows, kind):
    e = np.array([d["e"] for d in rows]); r = np.array([d["r"] for d in rows])
    le, lr = logit(e), logit(r)
    sig_other = np.array([d["pe"].get("sig_verify") == "OK" and not msok(d) for d in rows], float)
    dll = np.array([bool(d["pe"].get("is_dll")) for d in rows], float)
    net = np.array([bool(d["pe"].get("is_dotnet")) for d in rows], float)
    if kind == "linear":       # deployed form
        return np.c_[e, r]
    if kind == "logodds":
        return np.c_[le, lr]
    if kind == "logodds_x":
        return np.c_[le, lr, le * lr]
    if kind == "logodds_ctx":
        return np.c_[le, lr, le * lr, sig_other, dll, net]
    raise ValueError(kind)


def main():
    rt = {json.loads(l)["sha256"] for l in open(ROOT / "dataset/work/recent_test.jsonl") if json.loads(l)["label"] == 1}
    rtrain_b = {json.loads(l)["sha256"] for l in open(ROOT / "dataset/work/recent_train.jsonl") if json.loads(l)["label"] == 0}
    mal = [d for d in L("malware") if d["sha256"] in rt]
    good = [d for d in L("goodware") + L("local") + L("course") if d["sha256"] not in rtrain_b and not msok(d)]
    exe_g = np.array([not d["pe"].get("is_dll") for d in good])
    exe_m = np.array([not d["pe"].get("is_dll") for d in mal])
    print(f"fit set: malware {len(mal)} (EXE {exe_m.sum()}) | non-MS goodware {len(good)} (EXE {exe_g.sum()})")
    y = np.r_[np.ones(len(mal)), np.zeros(len(good))]
    isexe = np.r_[exe_m, exe_g]
    for kind in ("linear", "logodds", "logodds_x", "logodds_ctx"):
        X = np.r_[feats(mal, kind), feats(good, kind)]
        for target in (0.01, 0.0075):
            res = []
            for rep in range(5):
                rng = np.random.default_rng(rep)
                fold = np.empty(len(y), int)
                for cls in (0, 1):  # stratify by class x EXE
                    for ex in (0, 1):
                        ix = np.where((y == cls) & (isexe == ex))[0]; rng.shuffle(ix)
                        fold[ix] = np.arange(len(ix)) % 5
                for k in range(5):
                    tr, te = fold != k, fold == k
                    clf = LogisticRegression(C=1.0, class_weight="balanced", max_iter=2000).fit(X[tr], y[tr])
                    s = clf.decision_function(X)
                    gb_tr = s[tr & (y == 0)]; gbe_tr = s[tr & (y == 0) & isexe]
                    t = max(np.quantile(gb_tr, 1 - target), np.quantile(gbe_tr, 1 - target))
                    m_te = s[te & (y == 1)]; g_te = s[te & (y == 0)]; ge_te = s[te & (y == 0) & isexe]; me_te = s[te & (y == 1) & isexe]
                    res.append(((m_te > t).mean(), (me_te > t).mean(), (g_te > t).mean(), (ge_te > t).mean()))
            r = np.mean(res, axis=0)
            print(f"  {kind:12s} target {target:.2%}: TPR {r[0]:.3f} (EXE malware {r[1]:.3f}) | held-out FPR all {r[2]:.3%} EXE {r[3]:.3%}")
        clf = LogisticRegression(C=1.0, class_weight="balanced", max_iter=2000).fit(X, y)
        print(f"     coef {np.round(clf.coef_[0], 3).tolist()} intercept {clf.intercept_[0]:.3f}")


if __name__ == "__main__":
    main()
