#!/usr/bin/env python3
"""Accuracy / precision / recall / F1 for a running defender container.

    docker run --rm -m 1g -p 8080:8080 mlsec-defender
    python tools/eval_metrics.py --benign DIR --malicious DIR [--url http://127.0.0.1:8080]

Malware is the positive class. Files the server cannot be reached for or that
return a non-200 / unparseable reply are counted as errors and excluded from the
confusion matrix (listed at the end); use --errors-as-malware to count them as
detections instead, matching the server's fail-toward-detection policy.
"""
from __future__ import annotations

import argparse
import csv
import http.client
import json
import pathlib
import sys
import urllib.parse


def files_in(root: pathlib.Path) -> list[pathlib.Path]:
    if root.is_file():
        return [root]
    if root.is_dir():
        return sorted(p for p in root.rglob("*") if p.is_file())
    raise SystemExit(f"No such file or directory: {root}")


def classify(url: str, path: pathlib.Path, timeout: float) -> int:
    parts = urllib.parse.urlparse(url)
    conn = http.client.HTTPConnection(parts.hostname, parts.port or 80, timeout=timeout)
    try:
        conn.request("POST", "/", body=path.read_bytes(),
                     headers={"Content-Type": "application/octet-stream"})
        resp = conn.getresponse()
        body = resp.read()
        if resp.status != 200:
            raise RuntimeError(f"HTTP {resp.status}: {body[:100]!r}")
        result = json.loads(body)["result"]
        if result not in (0, 1):
            raise RuntimeError(f"unexpected result {result!r}")
        return int(result)
    finally:
        conn.close()


def check_server(url: str) -> None:
    """Fail fast: an accepted-but-silent port would otherwise cost one timeout per file."""
    parts = urllib.parse.urlparse(url)
    conn = http.client.HTTPConnection(parts.hostname, parts.port or 80, timeout=5)
    try:
        conn.request("GET", "/health")
        status = conn.getresponse().status
    except Exception as exc:  # noqa: BLE001
        raise SystemExit(f"Cannot reach the defender at {url} ({exc!r}). "
                         "Is the container running and its port published?")
    finally:
        conn.close()
    if status != 200:
        raise SystemExit(f"{url}/health returned HTTP {status}; is that the defender container?")


def ratio(num: float, den: float) -> float:
    return num / den if den else 0.0


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--benign", type=pathlib.Path, nargs="+", required=True)
    ap.add_argument("--malicious", type=pathlib.Path, nargs="+", required=True)
    ap.add_argument("--url", default="http://127.0.0.1:8080")
    ap.add_argument("--timeout", type=float, default=30)
    ap.add_argument("--errors-as-malware", action="store_true")
    ap.add_argument("--csv", type=pathlib.Path, help="write per-file predictions here")
    args = ap.parse_args()

    samples = [(p, 0) for r in args.benign for p in files_in(r)] + \
              [(p, 1) for r in args.malicious for p in files_in(r)]
    check_server(args.url)

    tp = fp = tn = fn = 0
    errors: list[tuple[pathlib.Path, str]] = []
    rows = []
    for i, (path, truth) in enumerate(samples, 1):
        try:
            pred = classify(args.url, path, args.timeout)
        except Exception as exc:  # noqa: BLE001 - report any failure per file
            if not args.errors_as_malware:
                errors.append((path, str(exc)))
                rows.append((str(path), truth, "error"))
                continue
            pred = 1
            errors.append((path, str(exc)))
        rows.append((str(path), truth, pred))
        if truth and pred:
            tp += 1
        elif truth:
            fn += 1
        elif pred:
            fp += 1
        else:
            tn += 1
        if i % 50 == 0:
            print(f"  {i}/{len(samples)}", file=sys.stderr)

    total = tp + fp + tn + fn
    precision, recall = ratio(tp, tp + fp), ratio(tp, tp + fn)
    f1 = ratio(2 * precision * recall, precision + recall)
    print(f"\nsamples scored: {total}  (errors: {len(errors)})")
    print(f"confusion:  TP={tp}  FP={fp}  TN={tn}  FN={fn}")
    print(f"accuracy   {ratio(tp + tn, total):.4f}")
    print(f"precision  {precision:.4f}")
    print(f"recall     {recall:.4f}   (TPR)")
    print(f"f1         {f1:.4f}")
    print(f"FPR        {ratio(fp, fp + tn):.4f}")
    if errors:
        print("\nerrors:")
        for path, msg in errors[:20]:
            print(f"  {path}: {msg}")
        if len(errors) > 20:
            print(f"  ... and {len(errors) - 20} more")

    if args.csv:
        with args.csv.open("w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["path", "label", "prediction"])
            w.writerows(rows)
        print(f"\nwrote {args.csv}")


if __name__ == "__main__":
    main()
