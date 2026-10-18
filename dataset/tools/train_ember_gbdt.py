#!/usr/bin/env python3
"""Ceiling-breaker: LightGBM on EMBER's full 2381-dim features.

Phase 1 — validate the accuracy ceiling. Uses the SAME EMBER samples our RF/NFS
models trained and tested on (matched by SHA-256 against dataset/work/ember_official),
but vectorizes the raw feature groups into EMBER's 2381-dim space instead of the NFS
hashed header+imports space. This isolates the effect of the FEATURE SPACE.

Vectorization uses the official `ember` package's PEFeatureExtractor, with a one-line
monkeypatch to SectionInfo for scikit-learn>=1.x FeatureHasher (which rejects a bare
single string as a sample). Vectors are cached to dataset/work/ember_v2/*.npy.
"""
from __future__ import annotations
import argparse, json, pathlib, random, sys, time
import numpy as np

# --- monkeypatch ember SectionInfo for new sklearn (entry must be [[entry]]) ---
import ember.features as _f
from sklearn.feature_extraction import FeatureHasher


def _section_fixed(self, raw_obj):
    sections = raw_obj['sections']
    general = [
        len(sections),
        sum(1 for s in sections if s['size'] == 0),
        sum(1 for s in sections if s['name'] == ""),
        sum(1 for s in sections if 'MEM_READ' in s['props'] and 'MEM_EXECUTE' in s['props']),
        sum(1 for s in sections if 'MEM_WRITE' in s['props']),
    ]
    def pair(key):
        return FeatureHasher(50, input_type="pair").transform(
            [[(s['name'], s[key]) for s in sections]]).toarray()[0]
    section_sizes_hashed = pair('size')
    section_entropy_hashed = pair('entropy')
    section_vsize_hashed = pair('vsize')
    entry_name_hashed = FeatureHasher(50, input_type="string").transform(
        [[raw_obj['entry']]]).toarray()[0]          # <-- fix: wrap the single string
    characteristics = [p for s in sections for p in s['props'] if s['name'] == raw_obj['entry']]
    characteristics_hashed = FeatureHasher(50, input_type="string").transform(
        [characteristics]).toarray()[0]
    return np.hstack([general, section_sizes_hashed, section_entropy_hashed,
                      section_vsize_hashed, entry_name_hashed,
                      characteristics_hashed]).astype(np.float32)


_f.SectionInfo.process_raw_features = _section_fixed
import ember  # noqa: E402

RAW = pathlib.Path("dataset/raw/ember2018")
CACHE = pathlib.Path("dataset/work/ember_v2")


def sha_labels(path, per_class, seed):
    """Sample per_class SHA-256s of each label from an ember_official split file."""
    by = {0: [], 1: []}
    for line in open(path):
        r = json.loads(line)
        if r.get("label") in (0, 1):
            by[r["label"]].append(r["sha256"])
    rng = random.Random(seed)
    out = {}
    for lab in (0, 1):
        pool = by[lab]
        if per_class and len(pool) > per_class:
            rng.shuffle(pool); pool = pool[:per_class]
        for s in pool:
            out[s] = lab
    return out


def vectorize_split(want, extractor):
    """Stream raw jsonl, vectorize rows whose sha is in `want` -> (X, y)."""
    X, y = [], []
    files = sorted(RAW.glob("train_features_*.jsonl")) + [RAW / "test_features.jsonl"]
    seen = 0
    for fp in files:
        for line in open(fp):
            r = json.loads(line)
            s = r.get("sha256")
            if s in want:
                X.append(extractor.process_raw_features(r))
                y.append(want[s])
                seen += 1
                if seen % 20000 == 0:
                    print(f"    vectorized {seen}/{len(want)}", file=sys.stderr)
    return np.asarray(X, dtype=np.float32), np.asarray(y, dtype=np.int8)


def metrics(scores, labels):
    order = np.argsort(-scores)
    s, l = scores[order], labels[order]
    P = int((labels == 1).sum()); N = int((labels == 0).sum())
    out = {}
    for target in (0.01, 0.001):
        # highest threshold with FPR <= target -> TPR there
        fp = np.cumsum(l == 0); tp = np.cumsum(l == 1)
        ok = np.where(fp <= target * N)[0]
        k = ok[-1] if len(ok) else -1
        out[f"tpr_at_fpr_{target}"] = float(tp[k] / P) if k >= 0 else 0.0
    # ROC-AUC
    ranks = np.argsort(np.argsort(scores))
    auc = (ranks[labels == 1].sum() - P * (P - 1) / 2) / (P * N)
    out["roc_auc"] = float(auc)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--train-per-class", type=int, default=100000)
    ap.add_argument("--test-per-class", type=int, default=25000)
    ap.add_argument("--iterations", type=int, default=1000)
    ap.add_argument("--seed", type=int, default=20260919)
    args = ap.parse_args()
    CACHE.mkdir(parents=True, exist_ok=True)
    ext = ember.PEFeatureExtractor(2)

    paths = {k: CACHE / f"{k}.npy" for k in ("X_train", "y_train", "X_test", "y_test")}
    if all(p.exists() for p in paths.values()):
        print("loading cached vectors...", file=sys.stderr)
        Xtr = np.load(paths["X_train"]); ytr = np.load(paths["y_train"])
        Xte = np.load(paths["X_test"]); yte = np.load(paths["y_test"])
    else:
        print("selecting matched train/test SHAs from ember_official...", file=sys.stderr)
        tr_want = sha_labels("dataset/work/ember_official/train.jsonl", args.train_per_class, args.seed)
        te_want = sha_labels("dataset/work/ember_official/test.jsonl", args.test_per_class, args.seed + 1)
        print(f"  train want {len(tr_want)}  test want {len(te_want)}; vectorizing (2381-dim)...", file=sys.stderr)
        t0 = time.time()
        want = {**{s: (0, l) for s, l in tr_want.items()}}  # placeholder
        # vectorize train then test (separate passes keep memory bounded)
        Xtr, ytr = vectorize_split(tr_want, ext)
        Xte, yte = vectorize_split(te_want, ext)
        print(f"  vectorized in {(time.time()-t0)/60:.1f} min; "
              f"train {Xtr.shape} test {Xte.shape}", file=sys.stderr)
        np.save(paths["X_train"], Xtr); np.save(paths["y_train"], ytr)
        np.save(paths["X_test"], Xte); np.save(paths["y_test"], yte)

    import lightgbm as lgb
    print(f"training LightGBM ({args.iterations} iters) on {Xtr.shape}...", file=sys.stderr)
    params = dict(boosting="gbdt", objective="binary", num_iterations=args.iterations,
                  learning_rate=0.05, num_leaves=2048, max_depth=15,
                  min_data_in_leaf=50, feature_fraction=0.5, verbose=-1, n_jobs=-1)
    t0 = time.time()
    booster = lgb.train(params, lgb.Dataset(Xtr, ytr))
    print(f"  trained in {(time.time()-t0)/60:.1f} min", file=sys.stderr)

    scores = booster.predict(Xte)
    m = metrics(scores, yte)
    print("\n=== EMBER-2381 LightGBM on matched EMBER temporal test ===")
    print(f"  test: {int((yte==0).sum())} benign / {int((yte==1).sum())} malicious")
    print(f"  ROC-AUC:        {m['roc_auc']:.4f}")
    print(f"  TPR @ 1%  FPR:  {m['tpr_at_fpr_0.01']*100:.1f}%   (rf_augmented 79.5%, rf_adv 76.7%, supplied 71.2%)")
    print(f"  TPR @ 0.1% FPR: {m['tpr_at_fpr_0.001']*100:.1f}%")
    outdir = pathlib.Path("dataset/models/ember_gbdt"); outdir.mkdir(parents=True, exist_ok=True)
    booster.save_model(str(outdir / "ember_gbdt.txt"))
    (outdir / "eval.json").write_text(json.dumps({"metrics": m,
        "n_test": int(yte.size), "n_train": int(ytr.size),
        "feature_space": "EMBER-2381", "iterations": args.iterations}, indent=2) + "\n")
    print(f"\nsaved model + eval to {outdir}")


if __name__ == "__main__":
    main()
