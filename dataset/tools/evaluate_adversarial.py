#!/usr/bin/env python3
"""Clean + adversarial evaluation of one or more NFS models, honestly.

Fixes applied after audit:
  * Attacks the HELD-OUT recent_test split (0 SHA overlap with training), never the
    full recent set that is 70% training data. Also reports the novel-feature subset
    (rows whose extracted features are not identical to any training row), the honest
    "generalization to unseen features" number.
  * Evaluates each model at its DEPLOYED threshold (its shipped 1%-FPR operating
    point), so the numbers describe what actually ships — not a re-derived cut.
  * Every rate carries a Wilson 95% CI; point estimates are noisy to ~±(CI/2).
  * Attack donors are held-out EMBER *test* benign, never training donors.
  * Attacks: A/B/C/E realizable & trained; F realizable & HELD OUT (generalization to
    an unseen mechanism); D the feature-space upper bound (never trained).

    python evaluate_adversarial.py \
      --models models/nfs_rf_augmented models/nfs_rf_adv \
      --thresholds 0.756536 0.820932 \
      --ember-test work/ember_official/test.jsonl \
      --recent-test work/recent_test.jsonl --recent-train work/recent_train.jsonl \
      --out results/adversarial_training.json
"""
from __future__ import annotations
import argparse, hashlib, json, math, pathlib, random, sys
import numpy as np

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "defender_product"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from defender.model import Model            # noqa: E402
from adv_transforms import TRANSFORMS       # noqa: E402
from fast_score import score_rows           # noqa: E402

ATTACK_ORDER = ["A", "B", "C", "E", "F", "D"]


def load(path, label=None, limit=None, seed=0):
    rows, rng = [], random.Random(seed)
    for line in open(path):
        r = json.loads(line)
        if label is not None and r.get("label") != label:
            continue
        if not isinstance(r.get("attributes"), dict):
            continue
        rows.append(r)
    if limit and len(rows) > limit:
        rng.shuffle(rows); rows = rows[:limit]
    return rows


def fingerprint(a):
    return hashlib.md5(json.dumps({k: a[k] for k in sorted(a)}, sort_keys=True).encode()).hexdigest()


def wilson(k, n, z=1.96):
    if n == 0:
        return [0.0, 0.0]
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return [max(0.0, (c - h) / d), min(1.0, (c + h) / d)]


def rate(scores, thr):
    k = int((scores > thr).sum()); n = int(scores.size)
    return {"rate": k / n if n else 0.0, "n": n, "k": k, "ci95": wilson(k, n)}


def calibrate(model, benign_rows, target=0.01):
    b = score_rows(model, benign_rows)
    for cut in np.unique(b):
        if float((b > cut).mean()) <= target:
            return float(cut)
    return 1.0


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--models", nargs="+", required=True)
    p.add_argument("--thresholds", nargs="+", type=float,
                   help="deployed threshold per model (else calibrate to 1% FPR)")
    p.add_argument("--calibrate", help="EMBER benign JSONL, used if --thresholds absent")
    p.add_argument("--ember-test", required=True)
    p.add_argument("--recent-test", required=True)
    p.add_argument("--recent-train", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--n-benign", type=int, default=30000)
    p.add_argument("--n-donors", type=int, default=2000)
    p.add_argument("--seed", type=int, default=99)
    args = p.parse_args()

    ember_mal = load(args.ember_test, label=1, limit=20000, seed=2)
    recent_mal = load(args.recent_test, label=1, seed=3)
    donors = load(args.ember_test, label=0, limit=args.n_donors, seed=4)
    train_fps = set()
    for line in open(args.recent_train):
        r = json.loads(line)
        if isinstance(r.get("attributes"), dict):
            train_fps.add(fingerprint(r["attributes"]))
    novel_idx = [i for i, m in enumerate(recent_mal)
                 if fingerprint(m["attributes"]) not in train_fps]
    cal_benign = load(args.calibrate, label=0, limit=args.n_benign, seed=1) if args.calibrate else None
    print(f"ember-mal {len(ember_mal)}  recent_test-mal {len(recent_mal)} "
          f"(novel-feature {len(novel_idx)})  donors {len(donors)}", file=sys.stderr)

    out = {"eval_set": "recent_test (held-out, 0 SHA overlap with training)",
           "n_recent_test": len(recent_mal), "n_novel_feature": len(novel_idx),
           "note": ("rates carry Wilson 95% CIs; models scored at their DEPLOYED "
                    "thresholds; F is a held-out attack mechanism, D the upper bound"),
           "attacks": ATTACK_ORDER, "models": {}}
    rng = random.Random(args.seed)
    chosen = [rng.choice(donors)["attributes"] for _ in recent_mal]

    for mi, mdir in enumerate(args.models):
        name = pathlib.Path(mdir).name
        model = Model(mdir, "training")
        if args.thresholds:
            thr = float(args.thresholds[mi])
        else:
            thr = calibrate(model, cal_benign, 0.01)
        emb = score_rows(model, ember_mal)
        rec = score_rows(model, recent_mal)
        rec_novel = rec[novel_idx]
        row = {"threshold": thr,
               "ember_tpr_at_1pct": rate(emb, thr),
               "recent_detect": rate(rec, thr),
               "recent_detect_novel": rate(rec_novel, thr),
               "adversarial": {}}
        caught0 = rec > thr
        for aname in ATTACK_ORDER:
            fn = TRANSFORMS[aname]
            adv = score_rows(model, [{"attributes": fn(m["attributes"], d, rng)}
                                     for m, d in zip(recent_mal, chosen)])
            r = rate(adv, thr)
            r["evasion_of_caught"] = float(((caught0) & (adv <= thr)).sum()
                                           / max(int(caught0.sum()), 1))
            row["adversarial"][aname] = r
        out["models"][name] = row
        a = row["adversarial"]
        pc = lambda d: f"{d['rate']*100:.0f}%[{d['ci95'][0]*100:.0f}-{d['ci95'][1]*100:.0f}]"
        print(f"\n{name}: thr={thr:.4f}  EMBER-TPR@1% {pc(row['ember_tpr_at_1pct'])}  "
              f"recent {pc(row['recent_detect'])}  recent-novel {pc(row['recent_detect_novel'])}")
        print("  after attack:  " + "  ".join(f"{k}:{pc(a[k])}" for k in ATTACK_ORDER))
    pathlib.Path(args.out).write_text(json.dumps(out, indent=2) + "\n")
    print(f"\nwrote {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
