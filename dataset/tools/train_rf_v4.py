#!/usr/bin/env python3
"""v4 NFS RandomForest = the rf_adv recipe + live-extracted goodware.

Diagnosis (v3): rf_adv's live-pipeline training rows were 1,021 malware vs 140 goodware,
so "extracted by the live pipeline" leaned malicious; its remaining FPs are modern native
EXEs (Go binaries, Python launchers) that ember_gbdt scores ~0. Fix (Arp P1 / Transcending
TRANSCEND source bias): add live goodware NFS dicts (corpus, local, goodware2) and give the
live rows of BOTH classes stratum-balanced weights (per is_dll x is_dotnet: equal benign
and malicious mass), so neither "live" nor file type predicts the label.

Recipe otherwise identical to train_nfs_adversarial.py (150k/class EMBER-NFS, recent_train,
60% A/B/C/E adversarial variants with benign-train donors, 100 trees, max_features 0.05).

  --cv K     K-fold, goodware held out by group (package/origin/product); writes OOF
             r scores for every live goodware row + recent_test malware (no export)
  --export   train on everything not in --holdout and export runtime arrays to --out
"""
from __future__ import annotations
import argparse, hashlib, json, pathlib, random, re, sys, time
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.utils.sparsefuncs import inplace_column_scale

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import train_nfs as T  # noqa: E402
from adv_transforms import make_adversarial  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[2]
C = ROOT / "dataset/work/live_cache"


def stratum(pe: dict) -> tuple[bool, bool]:
    return bool(pe.get("is_dll")), bool(pe.get("is_dotnet"))


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


def fold_of(group: str, k: int) -> int:
    return int(hashlib.sha256(norm_group(group).encode()).hexdigest(), 16) % k


def live_rows(corpora, holdout: set[str]):
    rows = []
    for c in corpora:
        for l in open(C / f"meta_{c}.jsonl"):
            d = json.loads(l)
            if not isinstance(d.get("nfs"), dict) or norm_group(d["group"]) in holdout:
                continue
            rows.append({"label": 0, "attributes": d["nfs"], "sha256": d["sha256"], "group": d["group"],
                         "stratum": stratum(d["pe"]), "corpus": c})
    return rows


def balanced_live_weights(rows, mass_factor: float):
    """Equal benign/malicious weight inside each stratum; stratum mass follows the live
    malware distribution; total live mass = mass_factor x n_live_malware."""
    mal = [r for r in rows if r["label"] == 1]; ben = [r for r in rows if r["label"] == 0]
    n_mal = len(mal); w = {}
    strata = {r["stratum"] for r in rows}
    for s in strata:
        ms = [r for r in mal if r["stratum"] == s]; bs = [r for r in ben if r["stratum"] == s]
        if not ms or not bs:
            for r in ms + bs:   # one-class stratum: keep it present but weak
                w[id(r)] = 0.1
            continue
        mass = mass_factor * len(ms)    # == mass_factor * n_mal * (share of malware in s)
        for r in ms:
            w[id(r)] = mass / len(ms)
        for r in bs:
            w[id(r)] = mass / len(bs)
    return w, n_mal


def build(args, holdout_groups: set[str], seed_offset: int = 0):
    rng = random.Random(args.seed + seed_offset)
    ember = T.load_rows(ROOT / "dataset/work/ember_official/train.jsonl", args.max_per_class, args.seed)
    mal_meta = {json.loads(l)["sha256"]: json.loads(l) for l in open(C / "meta_malware.jsonl")}
    recent = []
    for l in open(ROOT / "dataset/work/recent_train.jsonl"):
        r = json.loads(l)
        # goodware rows of recent_train are byte-identical copies of corpus goodware that
        # live_rows() already adds WITH holdout/fold filtering; adding them here unfiltered
        # leaked 4 sealed-holdout products into rf_v4 (v4 review, integrity check 1/5).
        if not r.get("attributes") or r["label"] == 0:
            continue
        m = mal_meta.get(r["sha256"])
        r["stratum"] = stratum(m["pe"]) if m else (False, False)
        recent.append(r)
    live_b = live_rows(args.live_corpora.split(","), holdout_groups) if args.live_corpora else []
    live = recent + live_b
    w_live, n_live_mal = balanced_live_weights(live, args.live_mass)
    rows = ember + live
    weights = [1.0] * len(ember) + [w_live.get(id(r), 1.0) for r in live]
    benign = [r for r in rows if r["label"] == 0]; malicious = [r for r in rows if r["label"] == 1]
    n_adv = int(args.adv_frac * len(malicious))
    adv = [{"label": 1, "attributes": make_adversarial(rng.choice(malicious)["attributes"],
                                                        rng.choice(benign)["attributes"], args.adv_mode, rng)}
           for _ in range(n_adv)]
    rows += adv; weights += [1.0] * n_adv
    labels = np.array([r["label"] for r in rows], dtype=np.int8)
    print(f"  rows {len(rows):,}: EMBER {len(ember):,} | live malware {n_live_mal} + live goodware {len(live_b):,} "
          f"(live mass x{args.live_mass}) | adversarial {n_adv:,}", file=sys.stderr, flush=True)
    matrix, encoder = T.build_matrix(rows, args.n_hash, None)
    scales = np.asarray(np.abs(matrix).max(axis=0).todense()).ravel(); scales[scales == 0] = 1.0
    inplace_column_scale(matrix, 1.0 / scales)
    matrix = matrix.astype(np.float32)
    forest = RandomForestClassifier(n_estimators=args.n_estimators, min_samples_leaf=2,
                                    max_features=float(args.max_features), n_jobs=-1, random_state=args.seed)
    t = time.time()
    forest.fit(matrix, labels, sample_weight=np.asarray(weights))
    print(f"  trained in {(time.time()-t)/60:.1f} min", file=sys.stderr, flush=True)
    return forest, encoder, scales, rows, labels


def score(forest, encoder, scales, attrs: list[dict], n_hash: int) -> np.ndarray:
    if not attrs:
        return np.zeros(0)
    m, _ = T.build_matrix([{"attributes": a} for a in attrs], n_hash, encoder)
    inplace_column_scale(m, 1.0 / scales)
    return forest.predict_proba(m.astype(np.float32))[:, 1]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--live-corpora", default="goodware,local,goodware2")
    ap.add_argument("--holdout", type=pathlib.Path, help="json list of goodware groups never trained on")
    ap.add_argument("--live-mass", type=float, default=5.0)
    ap.add_argument("--cv", type=int, default=0)
    ap.add_argument("--folds", default="", help="comma list of folds to run (default all)")
    ap.add_argument("--export", action="store_true")
    ap.add_argument("--out", type=pathlib.Path, default=ROOT / "defender_product/models/rf_v4")
    ap.add_argument("--max-per-class", type=int, default=150000)
    ap.add_argument("--adv-frac", type=float, default=0.6)
    ap.add_argument("--adv-mode", default="all")
    ap.add_argument("--n-hash", type=int, default=50000)
    ap.add_argument("--n-estimators", type=int, default=100)
    ap.add_argument("--max-features", default="0.05")
    ap.add_argument("--seed", type=int, default=20260919)
    args = ap.parse_args()
    holdout = set(json.load(open(args.holdout))) if args.holdout else set()
    excl = ROOT / "dataset/work/exp/v4_excluded_groups.json"     # greyware: never goodware
    if excl.exists():
        holdout |= set(json.load(open(excl)))
    holdout = {norm_group(g) for g in holdout}   # also drops older versions of a holdout product from other corpora
    exp = ROOT / "dataset/work/exp"; exp.mkdir(parents=True, exist_ok=True)

    rt = [json.loads(l) for l in open(ROOT / "dataset/work/recent_test.jsonl")]
    rt_mal = [r for r in rt if r["label"] == 1 and r.get("attributes")]

    if args.cv:
        allg = [json.loads(l) for c in args.live_corpora.split(",") for l in open(C / f"meta_{c}.jsonl")]
        allg = [d for d in allg if isinstance(d.get("nfs"), dict) and norm_group(d["group"]) not in holdout]
        folds = [int(x) for x in args.folds.split(",")] if args.folds else list(range(args.cv))
        for k in folds:
            out = exp / f"rf_v4_oof_fold{k}.json"
            if out.exists():
                print(f"fold {k}: exists, skipping", file=sys.stderr); continue
            held = {norm_group(d["group"]) for d in allg if fold_of(d["group"], args.cv) == k}
            print(f"fold {k}: holding out {len(held)} goodware groups", file=sys.stderr, flush=True)
            forest, enc, sc, _, _ = build(args, holdout | held, k)
            test = [d for d in allg if norm_group(d["group"]) in held]
            r_g = score(forest, enc, sc, [d["nfs"] for d in test], args.n_hash)
            r_m = score(forest, enc, sc, [r["attributes"] for r in rt_mal], args.n_hash)
            json.dump({"goodware": {d["sha256"]: float(v) for d, v in zip(test, r_g)},
                       "recent_test": {r["sha256"]: float(v) for r, v in zip(rt_mal, r_m)}}, open(out, "w"))
            print(f"fold {k}: wrote {out.name}", file=sys.stderr, flush=True)

    if args.export:
        forest, encoder, scales, rows, labels = build(args, holdout)
        out = args.out; out.mkdir(parents=True, exist_ok=True)
        info = T.export_forest(forest, out)
        np.save(out / "scales.npy", scales.astype("<f8"), allow_pickle=False)
        cats = [[str(v) for v in vals] for vals in encoder.categories_]
        n_features = len(T.NUMERICAL) + sum(map(len, cats)) + len(T.TEXTUAL) * args.n_hash
        schema = {"format_version": 1, "model_name": f"NFS_v4_live{args.live_mass}", "classes": [0, 1],
                  "malicious_class_index": 1, "n_features": n_features, **info,
                  "numerical_attributes": T.NUMERICAL, "categorical_attributes": T.CATEGORICAL,
                  "categorical_categories": cats, "categorical_handle_unknown": "ignore",
                  "textual_attributes": T.TEXTUAL,
                  "hashing": {a: {"n_features": args.n_hash, "token_pattern": T.TOKEN_PATTERN, "norm": "l2",
                                  "alternate_sign": True, "binary": False, "lowercase": True,
                                  "analyzer": "word", "ngram_range": [1, 1]} for a in T.TEXTUAL},
                  "training": {"rows": int(len(rows)), "benign": int((labels == 0).sum()),
                               "malicious": int((labels == 1).sum()), "live_corpora": args.live_corpora,
                               "live_mass": args.live_mass, "holdout_groups": len(holdout),
                               "adv_mode": args.adv_mode, "adv_frac": args.adv_frac, "seed": args.seed},
                  "equivalent_malware_decision": {"rule": "malware_probability > malware_threshold",
                                                  "malware_threshold": 0.25}}
        (out / "schema.json").write_text(json.dumps(schema, indent=2) + "\n")
        files = {}
        for path in sorted(out.glob("*.npy")):
            arr = np.load(path, mmap_mode="r", allow_pickle=False)
            files[path.name] = {"sha256": T.sha256(path), "bytes": path.stat().st_size,
                                "dtype": str(arr.dtype), "shape": list(arr.shape)}
        files["schema.json"] = {"sha256": T.sha256(out / "schema.json"), "bytes": (out / "schema.json").stat().st_size}
        (out / "manifest.json").write_text(json.dumps({"format_version": 1, "files": files,
            "total_artifact_bytes": sum(f["bytes"] for f in files.values()),
            "performance_claims": {"fpr_validated": False, "tpr_validated": False}}, indent=2) + "\n")
        print(f"exported {out}: {info['n_nodes']:,} nodes", file=sys.stderr)


if __name__ == "__main__":
    main()
