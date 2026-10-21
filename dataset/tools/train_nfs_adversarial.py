#!/usr/bin/env python3
"""NFS RandomForest trained with synthetic feature-space perturbations ("rf_adv").

Same feature space, same forest hyperparameters, same export format as
``train_nfs.py`` — the only change is that a fraction of the malicious class is
augmented with randomly generated attribute-dict perturbations (adv_transforms.py):
malware rows whose forgeable import/header fields are rewritten toward a random benign
donor, still labelled malicious. This is UNGUIDED augmentation: donors, rows and
transforms are drawn at random, with no model query, loss or gradient. Lucas et al.
(USENIX'23) distinguish exactly this kind of augmentation from attack-based training on
real binaries and show the former is weaker; the earlier wording here ("the Lucas
recipe, train on the attack") overstated it (review 2026-09-21, finding 3). No PE is
produced or executed; robustness measured with these transforms is feature-space only.

Donors for the training-time attack are the benign *training* rows. Evaluation uses
held-out donors (evaluate_adversarial.py), so a robustness gain reflects learning,
not memorization of specific benign import tokens.

    python train_nfs_adversarial.py --train work/ember_official/train.jsonl \
        --extra-train work/recent_train.jsonl --out models/nfs_rf_adv \
        --max-per-class 150000 --adv-frac 0.6 --adv-mode all

The deployed rf_adv was trained with --adv-mode all (A/B/C/E); this exact command
reproduces it. 'mix' (A/B/C only) trains a weaker model without the packing defense.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import random
import sys
import time

import numpy as np
from scipy import sparse
from sklearn.ensemble import RandomForestClassifier
from sklearn.utils.sparsefuncs import inplace_column_scale

import train_nfs as T
from adv_transforms import make_adversarial


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--train", type=pathlib.Path, required=True)
    p.add_argument("--out", type=pathlib.Path, required=True)
    p.add_argument("--extra-train", type=pathlib.Path)
    p.add_argument("--max-per-class", type=int, default=150000)
    p.add_argument("--adv-frac", type=float, default=0.6,
                   help="adversarial malware variants added, as a fraction of the "
                        "clean malicious count")
    p.add_argument("--adv-mode", default="all",
                   help="all (A/B/C/E, deployed) | mix (A/B/C) | A|B|C|E")
    p.add_argument("--adv-seed", type=int, default=1234)
    p.add_argument("--n-hash", type=int, default=50000)
    p.add_argument("--n-estimators", type=int, default=100)
    p.add_argument("--min-samples-leaf", type=int, default=2)
    p.add_argument("--max-features", default="0.05")
    p.add_argument("--n-jobs", type=int, default=-1)
    p.add_argument("--seed", type=int, default=20260919)
    args = p.parse_args()

    print("loading rows...", file=sys.stderr)
    rows = T.load_rows(args.train, args.max_per_class, args.seed)
    if args.extra_train:
        extra = [json.loads(l) for l in args.extra_train.open() if l.strip()]
        extra = [r for r in extra if r.get("attributes")]
        rows += extra
        print(f"  + {len(extra):,} extra rows from {args.extra_train.name}", file=sys.stderr)

    benign = [r for r in rows if r["label"] == 0 and isinstance(r.get("attributes"), dict)]
    malicious = [r for r in rows if r["label"] == 1 and isinstance(r.get("attributes"), dict)]
    n_adv = int(args.adv_frac * len(malicious))
    rng = random.Random(args.adv_seed)
    print(f"generating {n_adv:,} adversarial malware variants (mode={args.adv_mode}) "
          f"from {len(malicious):,} malware x {len(benign):,} benign donors...",
          file=sys.stderr)
    adv = []
    for _ in range(n_adv):
        m = rng.choice(malicious)["attributes"]
        d = rng.choice(benign)["attributes"]
        adv.append({"label": 1, "attributes": make_adversarial(m, d, args.adv_mode, rng)})
    rows = rows + adv
    rng.shuffle(rows)
    labels = np.array([r["label"] for r in rows], dtype=np.int8)
    print(f"  final: {len(rows):,} rows "
          f"({int((labels==0).sum()):,} benign / {int((labels==1).sum()):,} malicious "
          f"incl. {n_adv:,} adversarial)", file=sys.stderr)

    print("building design matrix...", file=sys.stderr)
    started = time.time()
    matrix, encoder = T.build_matrix(rows, args.n_hash, None)
    print(f"  {matrix.shape[0]:,} x {matrix.shape[1]:,} nnz={matrix.nnz:,} "
          f"{time.time()-started:.0f}s", file=sys.stderr)

    scales = np.asarray(np.abs(matrix).max(axis=0).todense()).ravel()
    scales[scales == 0] = 1.0
    inplace_column_scale(matrix, 1.0 / scales)
    matrix = matrix.astype(np.float32)

    try:
        max_features = float(args.max_features)
    except ValueError:
        max_features = args.max_features
    print(f"training RandomForest({args.n_estimators} trees)...", file=sys.stderr)
    started = time.time()
    forest = RandomForestClassifier(
        n_estimators=args.n_estimators, min_samples_leaf=args.min_samples_leaf,
        max_features=max_features, n_jobs=args.n_jobs, random_state=args.seed)
    forest.fit(matrix, labels)
    train_seconds = time.time() - started
    print(f"  trained in {train_seconds/60:.1f} min", file=sys.stderr)

    print("exporting arrays...", file=sys.stderr)
    info = T.export_forest(forest, args.out)
    np.save(args.out / "scales.npy", scales.astype("<f8"), allow_pickle=False)
    categories = [[str(v) for v in values] for values in encoder.categories_]
    n_features = len(T.NUMERICAL) + sum(map(len, categories)) + len(T.TEXTUAL) * args.n_hash
    assert n_features == matrix.shape[1], (n_features, matrix.shape[1])
    schema = {
        "format_version": 1,
        "model_name": f"NFS_adv_{args.adv_mode}_{args.adv_frac}",
        "classes": [0, 1], "malicious_class_index": 1,
        "n_features": n_features, **info,
        "numerical_attributes": T.NUMERICAL,
        "categorical_attributes": T.CATEGORICAL,
        "categorical_categories": categories,
        "categorical_handle_unknown": "ignore",
        "textual_attributes": T.TEXTUAL,
        "hashing": {a: {"n_features": args.n_hash, "token_pattern": T.TOKEN_PATTERN,
                        "norm": "l2", "alternate_sign": True, "binary": False,
                        "lowercase": True, "analyzer": "word", "ngram_range": [1, 1]}
                    for a in T.TEXTUAL},
        "training": {
            "source": str(args.train), "rows": int(len(rows)),
            "benign": int((labels == 0).sum()), "malicious": int((labels == 1).sum()),
            "adversarial_variants": n_adv, "adv_mode": args.adv_mode,
            "adv_frac": args.adv_frac, "adv_seed": args.adv_seed,
            "n_estimators": args.n_estimators, "min_samples_leaf": args.min_samples_leaf,
            "max_features": args.max_features, "seed": args.seed,
            "extra_train": str(args.extra_train) if args.extra_train else None,
            "sklearn_version": __import__("sklearn").__version__,
            "train_seconds": round(train_seconds, 1),
        },
        "equivalent_malware_decision": {"rule": "malware_probability > malware_threshold",
                                        "malware_threshold": 0.25},
    }
    (args.out / "schema.json").write_text(json.dumps(schema, indent=2) + "\n")
    files = {}
    for path in sorted(args.out.glob("*.npy")):
        array = np.load(path, mmap_mode="r", allow_pickle=False)
        files[path.name] = {"sha256": T.sha256(path), "bytes": path.stat().st_size,
                            "dtype": str(array.dtype), "shape": list(array.shape)}
    sp = args.out / "schema.json"
    files[sp.name] = {"sha256": T.sha256(sp), "bytes": sp.stat().st_size}
    (args.out / "manifest.json").write_text(json.dumps({
        "format_version": 1, "files": files,
        "total_artifact_bytes": sum(f["bytes"] for f in files.values()),
        "performance_claims": {"fpr_validated": False, "tpr_validated": False},
    }, indent=2) + "\n")
    total_mb = sum(f["bytes"] for f in files.values()) / 1e6
    print(f"wrote {args.out}: {info['n_nodes']:,} nodes, {total_mb:.0f} MB", file=sys.stderr)


if __name__ == "__main__":
    main()
