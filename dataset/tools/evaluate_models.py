#!/usr/bin/env python3
"""Compare detectors on a held-out set and report the metrics the goals name.

The headline is TPR at FPR = 1 %, not accuracy and not AUC: accuracy is
meaningless at realistic base rates, and AUC averages over operating points that
will never be used. Slices by month and by family are reported because a single
over-represented family can otherwise carry the number.

Inputs are either an NFS-schema JSONL (attributes already extracted) or
directories of raw PE files, so the same harness covers the EMBER temporal test
set, recent MalwareBazaar malware, and harvested goodware.

    python evaluate_models.py --model supplied=... retrained=... \
        --jsonl work/ember_official/test.jsonl --limit-per-class 25000
"""
from __future__ import annotations

import argparse
import collections
import json
import pathlib
import random
import sys
import time

import numpy as np

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "defender_product"))
from defender import features as feature_extraction   # noqa: E402
from defender.model import Model                      # noqa: E402


def metrics(scores: np.ndarray, labels: np.ndarray) -> dict:
    """ROC/PR summaries plus the operating points the challenge is graded on."""
    benign = scores[labels == 0]
    malicious = scores[labels == 1]
    out: dict = {"n_benign": int(benign.size), "n_malicious": int(malicious.size)}
    if benign.size == 0 or malicious.size == 0:
        return out
    order = np.argsort(-scores, kind="mergesort")
    ranked = labels[order]
    tp = np.cumsum(ranked == 1)
    fp = np.cumsum(ranked == 0)
    tpr = tp / malicious.size
    fpr = fp / benign.size
    out["roc_auc"] = float(np.trapezoid(tpr, fpr)) if fpr[-1] > 0 else float("nan")
    precision = tp / np.maximum(tp + fp, 1)
    out["pr_auc"] = float(np.trapezoid(precision, tpr))

    for target in (0.001, 0.01, 0.05):
        # Threshold must be strictly greater-than, matching the server's rule.
        allowed = np.flatnonzero(fpr <= target)
        if allowed.size:
            index = allowed[-1]
            cut = float(scores[order][index])
            achieved_fpr = float((benign > cut).mean())
            if achieved_fpr > target:              # ties pushed us over; step up
                candidates = np.unique(benign)
                higher = candidates[candidates >= cut]
                cut = float(higher[0]) if higher.size else cut
                achieved_fpr = float((benign > cut).mean())
            out[f"tpr_at_fpr_{target}"] = float((malicious > cut).mean())
            out[f"threshold_at_fpr_{target}"] = cut
            out[f"actual_fpr_{target}"] = achieved_fpr
        else:
            out[f"tpr_at_fpr_{target}"] = 0.0
    for threshold in (0.25, 0.5):
        out[f"fpr_at_{threshold}"] = float((benign > threshold).mean())
        out[f"tpr_at_{threshold}"] = float((malicious > threshold).mean())
    return out


def wilson(successes: int, total: int, z: float = 1.96) -> tuple[float, float]:
    if total == 0:
        return (float("nan"), float("nan"))
    p = successes / total
    denominator = 1 + z * z / total
    centre = (p + z * z / (2 * total)) / denominator
    margin = z * np.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denominator
    return (max(0.0, centre - margin), min(1.0, centre + margin))


def load_jsonl(path: pathlib.Path, limit_per_class: int, seed: int) -> list[dict]:
    pools: dict[int, list] = {0: [], 1: []}
    counts: collections.Counter = collections.Counter()
    rng = random.Random(seed)
    with path.open() as stream:
        for line in stream:
            row = json.loads(line)
            label = row["label"]
            counts[label] += 1
            pool = pools[label]
            if not limit_per_class or len(pool) < limit_per_class:
                pool.append(row)
            else:
                j = rng.randrange(counts[label])
                if j < limit_per_class:
                    pool[j] = row
    rows = pools[0] + pools[1]
    rng.shuffle(rows)
    return rows


def load_pe_dir(directory: pathlib.Path, label: int, limit: int,
                index: pathlib.Path | None) -> list[dict]:
    """Raw PE files (goodware) or password-protected archives (quarantined malware)."""
    meta: dict[str, dict] = {}
    if index and index.exists():
        with index.open() as stream:
            for line in stream:
                try:
                    record = json.loads(line)
                    meta[record["sha256"]] = record
                except (ValueError, KeyError):
                    continue
    rows: list[dict] = []
    paths = sorted(p for p in directory.rglob("*") if p.is_file())
    for path in paths:
        if limit and len(rows) >= limit:
            break
        digest = path.stem
        try:
            if path.suffix == ".zip":
                import pyzipper
                with pyzipper.AESZipFile(path) as archive:
                    archive.setpassword(b"infected")
                    blob = archive.read(archive.infolist()[0])
            else:
                blob = path.read_bytes()
            attributes = feature_extraction.extract(blob, "training")
        except Exception:
            # Unparseable input is what the server scores as 1; keep it in the set
            # rather than silently improving the numbers by dropping it.
            rows.append({"sha256": digest, "label": label, "attributes": None,
                         "meta": meta.get(digest, {})})
            continue
        rows.append({"sha256": digest, "label": label, "attributes": attributes,
                     "meta": meta.get(digest, {})})
    return rows


def score_rows(model: Model, rows: list[dict]) -> tuple[np.ndarray, float, int]:
    scores = np.empty(len(rows), dtype=np.float64)
    unparseable = 0
    started = time.perf_counter()
    for i, row in enumerate(rows):
        if row["attributes"] is None:
            scores[i] = 1.0            # fail toward detection, as the server does
            unparseable += 1
            continue
        scores[i] = model.probability(model.vectorize(row["attributes"]))
    return scores, time.perf_counter() - started, unparseable


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--model", nargs="+", required=True, metavar="NAME=DIR")
    parser.add_argument("--jsonl", type=pathlib.Path)
    parser.add_argument("--malware-dir", type=pathlib.Path)
    parser.add_argument("--malware-index", type=pathlib.Path)
    parser.add_argument("--goodware-dir", type=pathlib.Path)
    parser.add_argument("--goodware-index", type=pathlib.Path)
    parser.add_argument("--limit-per-class", type=int, default=25000)
    parser.add_argument("--seed", type=int, default=20260919)
    parser.add_argument("--out", type=pathlib.Path)
    parser.add_argument("--label", default="eval")
    args = parser.parse_args()

    rows: list[dict] = []
    if args.jsonl:
        rows += load_jsonl(args.jsonl, args.limit_per_class, args.seed)
    if args.malware_dir:
        rows += load_pe_dir(args.malware_dir, 1, args.limit_per_class, args.malware_index)
    if args.goodware_dir:
        rows += load_pe_dir(args.goodware_dir, 0, args.limit_per_class, args.goodware_index)
    if not rows:
        raise SystemExit("no evaluation data given")
    labels = np.array([r["label"] for r in rows], dtype=np.int8)
    print(f"{args.label}: {len(rows):,} samples "
          f"({int((labels == 0).sum()):,} benign / {int((labels == 1).sum()):,} malicious)",
          file=sys.stderr)

    report: dict = {"label": args.label, "n": len(rows),
                    "n_benign": int((labels == 0).sum()),
                    "n_malicious": int((labels == 1).sum()), "models": {}}
    for spec in args.model:
        name, _, directory = spec.partition("=")
        model = Model(directory, "training")
        scores, seconds, unparseable = score_rows(model, rows)
        summary = metrics(scores, labels)
        summary["seconds_total"] = round(seconds, 1)
        summary["ms_per_sample"] = round(1000 * seconds / len(rows), 3)
        summary["unparseable"] = unparseable
        summary["model_dir"] = directory
        summary["n_nodes"] = int(model.schema.get("n_nodes", 0))

        malicious_mask = labels == 1
        cut = summary.get("threshold_at_fpr_0.01")
        if cut is not None:
            hits = int((scores[malicious_mask] > cut).sum())
            low, high = wilson(hits, int(malicious_mask.sum()))
            summary["tpr_at_fpr_0.01_ci95"] = [round(low, 4), round(high, 4)]
            # Per-family / per-month slices at that same operating point.
            slices: dict[str, dict] = {}
            for row, score in zip(rows, scores):
                if row["label"] != 1:
                    continue
                key = (row.get("meta", {}).get("family")
                       or row.get("appeared") or "unknown")
                bucket = slices.setdefault(key, {"n": 0, "detected": 0})
                bucket["n"] += 1
                bucket["detected"] += int(score > cut)
            summary["slices"] = {k: {**v, "tpr": round(v["detected"] / v["n"], 4)}
                                 for k, v in sorted(slices.items())}
        report["models"][name] = summary
        print(f"  {name:12s} scored in {seconds:6.1f}s "
              f"({summary['ms_per_sample']:.2f} ms/sample)", file=sys.stderr)

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({n: {k: v for k, v in s.items() if k != "slices"}
                      for n, s in report["models"].items()}, indent=2))


if __name__ == "__main__":
    main()
