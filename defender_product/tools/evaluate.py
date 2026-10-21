#!/usr/bin/env python3
"""Measure FPR/TPR against labelled samples and pick an operating threshold.

Scoring happens in-process by default, which yields probabilities and therefore a
full threshold sweep. ``--url`` instead drives a running container over HTTP, which
only yields 0/1 at the deployed threshold but exercises the real delivered path.

    python tools/evaluate.py --benign DIR --malicious DIR
    python tools/evaluate.py --benign DIR --malicious DIR --url http://127.0.0.1:8080

Unreadable or unparseable samples are scored 1.0, matching the server's choice to
fail toward detection; they are also reported separately, because that choice is
what turns a corrupt benign file into a false positive.

Over HTTP, an answer that arrives after ``--deadline`` seconds (default 5.0, the
challenge's limit), or not at all, or malformed, is not a detection: malware counts as
a miss, goodware as a false positive, and every such sample is listed under
operational errors. Every submitted sample stays in the denominator.
"""
from __future__ import annotations

import argparse
import http.client
import json
import pathlib
import statistics
import sys
import time
import urllib.parse
from typing import Iterable

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

UNPARSEABLE_SCORE = 1.0


def iter_samples(roots: Iterable[pathlib.Path]) -> list[pathlib.Path]:
    found: list[pathlib.Path] = []
    for root in roots:
        if root.is_file():
            found.append(root)
        elif root.is_dir():
            found.extend(sorted(p for p in root.rglob("*") if p.is_file()))
        else:
            raise SystemExit(f"No such file or directory: {root}")
    return found


def score_locally(paths: list[pathlib.Path], model_dir: str, mode: str):
    from defender.model import Model
    model = Model(model_dir, mode)
    for path in paths:
        started = time.perf_counter()
        try:
            probability = model.predict(path.read_bytes())["malware_probability"]
            failed = False
        except Exception:
            probability, failed = UNPARSEABLE_SCORE, True
        yield path, probability, failed, time.perf_counter() - started


DEADLINE_SECONDS = 5.0   # the challenge's per-sample limit: a later answer is no answer


def score_over_http(paths: list[pathlib.Path], url: str, deadline: float = DEADLINE_SECONDS):
    """Drive a running server. A sample whose answer is late (> ``deadline``), missing,
    malformed or transport-failed is NOT a detection: the challenge scores it as an
    evasion (review 2026-09-21, finding 4). Such samples stay in the denominator and are
    yielded with ``failed=True`` and a score that counts against the detector
    (1.0 for benign = false positive, 0.0 for malware = miss); the caller reports them
    separately as operational errors."""
    parts = urllib.parse.urlparse(url)
    for path in paths:
        body = path.read_bytes()
        started = time.perf_counter()
        connection = http.client.HTTPConnection(parts.hostname, parts.port or 80, timeout=deadline)
        error = None
        payload: dict = {}
        try:
            connection.request("POST", "/", body=body,
                               headers={"Content-Type": "application/octet-stream"})
            response = connection.getresponse()
            raw = response.read()
            payload = json.loads(raw)
        except Exception as exc:                     # timeout, reset, refused, bad JSON
            error = f"{type(exc).__name__}: {exc}"[:120]
        finally:
            connection.close()
        elapsed = time.perf_counter() - started
        result = payload.get("result") if isinstance(payload, dict) else None
        if error is None and result not in (0, 1):
            error = f"malformed response: {str(payload)[:60]}"
        if error is None and elapsed > deadline:
            error = f"late: {elapsed:.3f}s > {deadline:.1f}s"
        if error is not None:
            yield path, None, error, elapsed       # score decided by the caller per label
            continue
        # Only the decision is observable here, so map it onto the score axis.
        yield path, float(result), False, elapsed


def sweep(benign: list[float], malicious: list[float], target_fpr: float, min_tpr: float):
    candidates = sorted({round(value, 12) for value in benign + malicious} | {0.0, 1.0})
    rows = []
    for threshold in candidates:
        false_positives = sum(1 for value in benign if value > threshold)
        true_positives = sum(1 for value in malicious if value > threshold)
        rows.append({
            "threshold": threshold,
            "fpr": false_positives / len(benign) if benign else float("nan"),
            "tpr": true_positives / len(malicious) if malicious else float("nan"),
        })
    feasible = [row for row in rows if row["fpr"] <= target_fpr]
    best = max(feasible, key=lambda row: (row["tpr"], -row["threshold"])) if feasible else None
    return rows, best


def report(name: str, scores: list[float], failures: int) -> dict:
    if not scores:
        return {"count": 0}
    ordered = sorted(scores)
    return {
        "count": len(scores),
        "unparseable": failures,
        "mean": statistics.fmean(scores),
        "p50": ordered[len(ordered) // 2],
        "p95": ordered[int(len(ordered) * 0.95) - 1] if len(ordered) > 1 else ordered[0],
        "max": ordered[-1],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--benign", type=pathlib.Path, nargs="*", default=[],
                        help="files or directories of goodware")
    parser.add_argument("--malicious", type=pathlib.Path, nargs="*", default=[],
                        help="files or directories of malware")
    parser.add_argument("--model", default="models/nfs")
    parser.add_argument("--feature-mode", default="training", choices=("training", "legacy"))
    parser.add_argument("--threshold", type=float, default=0.25,
                        help="deployed decision threshold to report at")
    parser.add_argument("--target-fpr", type=float, default=0.01)
    parser.add_argument("--min-tpr", type=float, default=0.95)
    parser.add_argument("--url", help="score through a running server instead of in-process")
    parser.add_argument("--deadline", type=float, default=DEADLINE_SECONDS,
                        help="per-sample HTTP deadline; later/missing answers count against the detector")
    parser.add_argument("--json", type=pathlib.Path, help="write the full report here")
    args = parser.parse_args()

    if not args.benign and not args.malicious:
        parser.error("give --benign and/or --malicious samples")

    groups = {"benign": iter_samples(args.benign), "malicious": iter_samples(args.malicious)}
    scores: dict[str, list[float]] = {"benign": [], "malicious": []}
    failures = {"benign": 0, "malicious": 0}
    operational: dict[str, list[dict]] = {"benign": [], "malicious": []}
    latencies: list[float] = []
    per_sample = []

    for label, paths in groups.items():
        if not paths:
            continue
        runner = (score_over_http(paths, args.url, args.deadline) if args.url
                  else score_locally(paths, args.model, args.feature_mode))
        for path, probability, failed, elapsed in runner:
            if probability is None:                  # HTTP: late / missing / malformed answer
                # counts against the detector either way, and is reported separately
                probability = 1.0 if label == "benign" else 0.0
                operational[label].append({"path": str(path), "error": failed, "seconds": round(elapsed, 4)})
            scores[label].append(probability)
            failures[label] += bool(failed)
            latencies.append(elapsed)
            per_sample.append({"path": str(path), "label": label,
                               "score": probability, "failed": failed,
                               "seconds": round(elapsed, 4)})
        print(f"{label}: scored {len(scores[label])} samples"
              + (f" ({len(operational[label])} late/failed, counted against the detector)" if operational[label] else ""),
              file=sys.stderr)

    benign, malicious = scores["benign"], scores["malicious"]
    fpr = sum(1 for v in benign if v > args.threshold) / len(benign) if benign else None
    tpr = sum(1 for v in malicious if v > args.threshold) / len(malicious) if malicious else None

    print(f"\n=== at the deployed threshold {args.threshold} ===")
    if fpr is not None:
        print(f"FPR  {fpr:7.4%}  ({sum(1 for v in benign if v > args.threshold)}/{len(benign)})"
              f"   target <= {args.target_fpr:.2%}   {'PASS' if fpr <= args.target_fpr else 'FAIL'}")
    if tpr is not None:
        print(f"TPR  {tpr:7.4%}  ({sum(1 for v in malicious if v > args.threshold)}/{len(malicious)})"
              f"   target >= {args.min_tpr:.2%}   {'PASS' if tpr >= args.min_tpr else 'FAIL'}")

    print("\n=== score distribution ===")
    for label in ("benign", "malicious"):
        stats = report(label, scores[label], failures[label])
        if stats["count"]:
            print(f"{label:9s} n={stats['count']:<6d} unparseable={stats['unparseable']:<4d} "
                  f"mean={stats['mean']:.4f} p50={stats['p50']:.4f} "
                  f"p95={stats['p95']:.4f} max={stats['max']:.4f}")

    best = None
    if args.url:
        print("\n(threshold sweep needs probabilities; rerun without --url)")
    elif benign and malicious:
        rows, best = sweep(benign, malicious, args.target_fpr, args.min_tpr)
        print(f"\n=== best threshold with FPR <= {args.target_fpr:.2%} ===")
        if best is None:
            print("No threshold reaches the FPR target on this sample set.")
        else:
            verdict = "meets" if best["tpr"] >= args.min_tpr else "MISSES"
            print(f"threshold {best['threshold']:.6f} -> FPR {best['fpr']:.4%}, "
                  f"TPR {best['tpr']:.4%}  ({verdict} the {args.min_tpr:.0%} TPR goal)")

    if latencies:
        ordered = sorted(latencies)
        print(f"\nlatency s: mean {statistics.fmean(ordered):.4f}  "
              f"p95 {ordered[int(len(ordered)*0.95)-1]:.4f}  max {ordered[-1]:.4f}  "
              f"deadline {args.deadline:.1f}  over deadline: {sum(1 for v in ordered if v > args.deadline)}")
    if any(operational.values()):
        print("\n=== operational errors (late, missing, malformed, transport) — counted against the detector ===")
        for label, rows in operational.items():
            for row in rows:
                print(f"  {label:9s} {row['seconds']:7.3f}s  {row['error']}  {row['path']}")

    if args.json:
        args.json.write_text(json.dumps({
            "threshold": args.threshold, "feature_mode": args.feature_mode,
            "fpr": fpr, "tpr": tpr, "recommended": best,
            "distribution": {k: report(k, scores[k], failures[k]) for k in scores},
            "deadline_seconds": args.deadline if args.url else None,
            "operational_errors": operational,
            "samples": per_sample,
        }, indent=2) + "\n")
        print(f"\nwrote {args.json}")


if __name__ == "__main__":
    main()
