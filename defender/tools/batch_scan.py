#!/usr/bin/env python3
"""
Batch-scan files in a directory by posting their bytes to a running defender service.

Usage examples:
  python3 tools/batch_scan.py --dir /path/to/folder --out-csv results.csv
  python3 tools/batch_scan.py --dir /path --recursive --workers 8 --pattern "*.exe" --out-csv results.csv

The server is expected at --url (default http://127.0.0.1:8080/) and accepts a single file per request.
This script handles iterating over files for you and writes a CSV summary.
"""
import argparse
import csv
import fnmatch
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Iterable, List, Tuple

try:
    # Prefer requests if available for better error messages and streaming
    import requests  # type: ignore
    HAVE_REQUESTS = True
except Exception:
    import urllib.request
    import urllib.error
    HAVE_REQUESTS = False


def iter_files(root: str, recursive: bool, pattern: str | None, max_files: int | None) -> List[str]:
    files: List[str] = []
    if recursive:
        for dirpath, _dirnames, filenames in os.walk(root):
            for name in filenames:
                path = os.path.join(dirpath, name)
                if pattern and not fnmatch.fnmatch(name, pattern):
                    continue
                files.append(path)
                if max_files and len(files) >= max_files:
                    return files
    else:
        try:
            for name in sorted(os.listdir(root)):
                path = os.path.join(root, name)
                if not os.path.isfile(path):
                    continue
                if pattern and not fnmatch.fnmatch(name, pattern):
                    continue
                files.append(path)
                if max_files and len(files) >= max_files:
                    return files
        except FileNotFoundError:
            raise SystemExit(f"Directory not found: {root}")
    return files


def scan_with_requests(url: str, path: str, timeout: float) -> Tuple[str, int | None, str | None]:
    try:
        with open(path, "rb") as f:
            resp = requests.post(url, data=f, headers={"Content-Type": "application/octet-stream"}, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
        result = data.get("result")
        return path, int(result) if result is not None else None, None
    except Exception as e:
        return path, None, str(e)


def scan_with_urllib(url: str, path: str, timeout: float) -> Tuple[str, int | None, str | None]:
    try:
        with open(path, "rb") as f:
            data = f.read()
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/octet-stream"}, method="POST")
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # type: ignore[attr-defined]
            raw = resp.read().decode("utf-8", errors="replace")
        obj = json.loads(raw)
        result = obj.get("result")
        return path, int(result) if result is not None else None, None
    except Exception as e:
        return path, None, str(e)


def main() -> None:
    ap = argparse.ArgumentParser(description="Batch-scan files against defender service")
    ap.add_argument("--dir", required=True, help="Directory containing files to scan")
    ap.add_argument("--url", default="http://127.0.0.1:8080/", help="Defender endpoint URL")
    ap.add_argument("--recursive", action="store_true", help="Recurse into subdirectories")
    ap.add_argument("--pattern", default=None, help="Glob pattern to filter files (e.g. *.exe)")
    ap.add_argument("--workers", type=int, default=os.cpu_count() or 4, help="Parallel worker threads")
    ap.add_argument("--timeout", type=float, default=30.0, help="Per-request timeout in seconds")
    ap.add_argument("--max-files", type=int, default=None, help="Limit number of files to scan")
    ap.add_argument("--out-csv", default=None, help="Write results to CSV path (columns: path,result,status,error)")
    ap.add_argument("--print-jsonl", action="store_true", help="Also print results as JSONL to stdout")
    args = ap.parse_args()

    files = iter_files(args.dir, args.recursive, args.pattern, args.max_files)
    if not files:
        print("No files matched.")
        return

    print(f"Scanning {len(files)} files with {args.workers} workers against {args.url} ...")
    t0 = time.time()

    scan_fn = scan_with_requests if HAVE_REQUESTS else scan_with_urllib
    results: List[Tuple[str, int | None, str | None]] = []

    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as ex:
        fut2path = {ex.submit(scan_fn, args.url, p, args.timeout): p for p in files}
        for fut in as_completed(fut2path):
            path, result, err = fut.result()
            results.append((path, result, err))
            if args.print_jsonl:
                obj = {"path": path, "result": result, "error": err}
                print(json.dumps(obj, ensure_ascii=False))

    # Summarize
    ok = sum(1 for _, r, e in results if e is None and r is not None)
    errs = sum(1 for _, r, e in results if e is not None or r is None)
    mal = sum(1 for _, r, e in results if e is None and r == 1)
    ben = sum(1 for _, r, e in results if e is None and r == 0)
    dur = time.time() - t0
    print(f"Done in {dur:.2f}s: ok={ok}, errors={errs}, malicious={mal}, benign={ben}")

    # CSV
    if args.out_csv:
        out_path = args.out_csv
        os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
        with open(out_path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["path", "result", "status", "error"])  # status: ok|error
            for path, result, err in results:
                status = "ok" if err is None and result is not None else "error"
                w.writerow([path, result if result is not None else "", status, err if err else ""]) 
        print(f"Wrote CSV: {out_path}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Interrupted.")
        sys.exit(130)
