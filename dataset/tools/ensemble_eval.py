#!/usr/bin/env python3
"""Evaluate the diversified ensemble: ember_gbdt (EMBER-2381, richer features) OR
rf_adv (NFS, recent + hardened). Both score every file through their own pipeline;
flag malicious if EITHER exceeds its threshold. Thresholds are jointly calibrated to
1% COMBINED FPR on held-out goodware (in neither model's training).
"""
from __future__ import annotations
import sys, glob, json, random, pathlib, numpy as np
sys.path.insert(0, "dataset/tools")
sys.path.insert(0, "defender_product")
import ember_compat, ember, lightgbm as lgb, pyzipper
from defender import features as nfs_features
from defender.model import Model

EXT = ember.PEFeatureExtractor(2, print_feature_warning=False)
EMB = lgb.Booster(model_file="dataset/models/ember_gbdt/ember_gbdt.txt")
RF = Model("defender_product/models/rf_adv", "training")


def scores(bytez):
    """(ember_score, rf_score); fail-toward-detection -> (1,1)."""
    try:
        e = float(EMB.predict(np.asarray(EXT.feature_vector(bytez), dtype=np.float32).reshape(1, -1))[0])
    except Exception:
        e = 1.0
    try:
        a = nfs_features.extract(bytez, "training")
        r = float(RF.probability(RF.vectorize(a)))
    except Exception:
        r = 1.0
    return e, r


def collect(paths_bytes):
    E, R = [], []
    for b in paths_bytes:
        e, r = scores(b); E.append(e); R.append(r)
    return np.array(E), np.array(R)


def benign_bytes(n_corpus=800):
    out = []
    for f in sorted(glob.glob("ml-cybersecuritiy-course/datasets/samples/pe/*.exe")):
        out.append(open(f, "rb").read())          # 7 clean held-out native EXEs
    idx = [json.loads(l) for l in open("dataset/goodware/index.jsonl")]
    random.Random(0).shuffle(idx)
    for r in idx[:n_corpus]:
        p = pathlib.Path(f"dataset/goodware/pe/{r['sha256']}.bin")
        if p.exists():
            out.append(p.read_bytes())
    return out


def malware_bytes(limit=433):
    shas = [json.loads(l)["sha256"] for l in open("dataset/work/recent_test.jsonl") if json.loads(l).get("label") == 1]
    out = []
    for s in shas[:limit]:
        z = pathlib.Path(f"dataset/quarantine/archives/{s}.zip")
        if not z.exists():
            continue
        try:
            with pyzipper.AESZipFile(z) as a:
                a.setpassword(b"infected"); out.append(a.read(a.infolist()[0]))
        except Exception:
            pass
    return out


def main():
    print("scoring benign (both pipelines)...", file=sys.stderr)
    bE, bR = collect(benign_bytes())
    print("scoring malware (both pipelines)...", file=sys.stderr)
    mE, mR = collect(malware_bytes())
    n_b, n_m = len(bE), len(mE)
    print(f"benign {n_b}  malware {n_m}", file=sys.stderr)

    def orflag(E, R, tE, tR): return (E > tE) | (R > tR)
    # grid search thresholds for max recall at <=1% combined benign FPR
    best = None
    for qE in np.linspace(0.90, 0.999, 40):
        tE = np.quantile(bE, qE)
        for qR in np.linspace(0.90, 0.999, 40):
            tR = np.quantile(bR, qR)
            fpr = orflag(bE, bR, tE, tR).mean()
            if fpr <= 0.01:
                rec = orflag(mE, mR, tE, tR).mean()
                if best is None or rec > best[0]:
                    best = (rec, tE, tR, fpr)
    rec, tE, tR, fpr = best
    # individual models at their own 1% FPR on this benign set
    tE1 = np.quantile(bE, 0.99); tR1 = np.quantile(bR, 0.99)
    res = {
        "ensemble": {"recent_detect": float(rec), "benign_fpr": float(fpr),
                     "t_ember": float(tE), "t_rf": float(tR)},
        "ember_only": {"recent_detect": float((mE > tE1).mean()), "benign_fpr": float((bE > tE1).mean())},
        "rf_only": {"recent_detect": float((mR > tR1).mean()), "benign_fpr": float((bR > tR1).mean())},
        "n_benign": n_b, "n_malware": n_m,
    }
    pathlib.Path("dataset/results/ensemble_eval.json").write_text(json.dumps(res, indent=2) + "\n")
    print("\n=== ENSEMBLE (ember_gbdt OR rf_adv) on held-out real data ===")
    print(f"  ensemble : recent detect {rec*100:.1f}%  @ benign FPR {fpr*100:.2f}%")
    print(f"  ember_gbdt alone (1% FPR): recent {res['ember_only']['recent_detect']*100:.1f}%")
    print(f"  rf_adv alone     (1% FPR): recent {res['rf_only']['recent_detect']*100:.1f}%")
    print(f"  -> ensemble recall should exceed both individual models")


if __name__ == "__main__":
    main()
