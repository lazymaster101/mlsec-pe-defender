#!/usr/bin/env python3
"""Collect the most recent in-the-wild Windows PE malware from MalwareBazaar by FILE TYPE,
not by family: the latest N `exe` (and optionally `dll`) uploads, whatever family they are,
including untagged ones. This complements collect_malwarebazaar.py (family-stratified,
40 per family, 38 commodity families): the recent feed is where new builders, new
packers and family-less loaders appear first, and that is exactly the concept drift a
static detector loses TPR to (THREAT_MODEL.md section 5).

Hygiene:
  * --exclude-manifest: every sha256 in the course validation manifest is refused, so no
    evaluation sample can enter training. Feature-identical near-duplicates of evaluation
    samples are removed later, after extraction (see train_v5.py).
  * Samples stay INERT on disk: only MalwareBazaar's password-protected archive is written
    (mode 0600). Feature extraction decrypts in memory. Nothing here executes a sample.
  * --since: keep only samples first seen on/after this date (YYYY-MM-DD).

    export MB_AUTH_KEY=...      # or put the key in ./.mb_key (git-ignored)
    python collect_mb_recent.py --out dataset/quarantine --file-types exe --limit 1000 \
        --since 2026-09-01 --exclude-manifest csce704-.../manifest.json
"""
from __future__ import annotations
import argparse, collections, json, os, pathlib, ssl, sys, time, urllib.error, urllib.parse, urllib.request

API = "https://mb-api.abuse.ch/api/v1/"


def _ssl_context() -> ssl.SSLContext:
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        return ssl.create_default_context()


_SSL = _ssl_context()


def api(payload: dict, key: str, timeout: int = 120, attempts: int = 4):
    """One API call with retry/backoff on transient failures (5xx, timeouts, resets)."""
    data = urllib.parse.urlencode(payload).encode()
    last = None
    for i in range(attempts):
        try:
            req = urllib.request.Request(API, data=data, headers={"Auth-Key": key})
            with urllib.request.urlopen(req, timeout=timeout, context=_SSL) as r:
                raw = r.read()
            break
        except urllib.error.HTTPError as e:
            last = e
            if e.code < 500 and e.code != 429:
                raise
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as e:
            last = e
        wait = 3 * (2 ** i)
        print(f"    transient error ({last}); retry in {wait}s", file=sys.stderr)
        time.sleep(wait)
    else:
        raise RuntimeError(f"MalwareBazaar API failed after {attempts} attempts: {last}")
    if raw[:2] == b"PK":
        return raw
    try:
        return json.loads(raw)
    except ValueError:
        return {"query_status": "non_json", "raw": raw[:200].decode("utf-8", "replace")}


def load_key(root: pathlib.Path) -> str:
    key = os.environ.get("MB_AUTH_KEY", "").strip()
    if not key:
        p = root / ".mb_key"
        if p.exists():
            key = p.read_text().strip()
    if not key:
        raise SystemExit("Set MB_AUTH_KEY or create <repo>/.mb_key (git-ignored)")
    return key


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", type=pathlib.Path, required=True)
    ap.add_argument("--file-types", default="exe", help="comma list of MalwareBazaar file types (exe,dll); '' to skip")
    ap.add_argument("--tags", default="", help="comma list of MalwareBazaar tags to pull via get_taginfo "
                    "(e.g. Rust,golang,Nim,loader): modern build toolchains EMBER-2018 never saw")
    ap.add_argument("--limit", type=int, default=1000, help="rows per file type (API max 1000)")
    ap.add_argument("--since", default=None, help="keep first_seen >= YYYY-MM-DD")
    ap.add_argument("--max-bytes", type=int, default=32 * 1024 * 1024)
    ap.add_argument("--max-download", type=int, default=1000)
    ap.add_argument("--exclude-manifest", type=pathlib.Path, action="append", default=[],
                    help="course manifest.json; its sha256s are never downloaded")
    ap.add_argument("--index-only", action="store_true")
    ap.add_argument("--sleep", type=float, default=0.4)
    args = ap.parse_args()
    root = pathlib.Path(__file__).resolve().parents[2]
    key = load_key(root)

    banned = set()
    for m in args.exclude_manifest:
        banned |= {s["sha256"].lower() for s in json.load(open(m))["samples"]}
    print(f"{len(banned)} evaluation hashes banned from collection", file=sys.stderr)

    archives = args.out / "archives"; archives.mkdir(parents=True, exist_ok=True)
    index_path = args.out / "index.jsonl"
    have = set()
    if index_path.exists():
        for line in index_path.open():
            try:
                have.add(json.loads(line)["sha256"])
            except (ValueError, KeyError):
                continue
    print(f"{len(have)} samples already indexed", file=sys.stderr)

    selected, refused = [], 0
    queries = [({"query": "get_file_type", "file_type": ft, "limit": min(args.limit, 1000)}, f"type:{ft}")
               for ft in args.file_types.split(",") if ft]
    queries += [({"query": "get_taginfo", "tag": t, "limit": min(args.limit, 1000)}, f"tag:{t}")
                for t in args.tags.split(",") if t]
    PE_TYPES = {"exe", "dll"}
    for payload, label in queries:
        try:
            res = api(payload, key)
        except Exception as e:
            print(f"  {label}: skipped ({e})", file=sys.stderr)
            continue
        if not isinstance(res, dict) or res.get("query_status") != "ok":
            print(f"  {label}: {res.get('query_status') if isinstance(res, dict) else 'binary'}", file=sys.stderr)
            continue
        rows = [r for r in (res.get("data") or []) if r.get("file_type") in PE_TYPES]
        print(f"  {label}: {len(rows)} PE rows of {len(res.get('data') or [])}", file=sys.stderr)
        for row in rows:
            sha = (row.get("sha256_hash") or "").lower(); size = int(row.get("file_size") or 0)
            if len(sha) != 64 or sha in have or not (0 < size <= args.max_bytes):
                continue
            if sha in banned:
                refused += 1; continue
            if args.since and (row.get("first_seen") or "") < args.since:
                continue
            have.add(sha)
            selected.append({"sha256": sha, "family": row.get("signature") or "untagged",
                             "reported_signature": row.get("signature"), "file_type": row.get("file_type"),
                             "file_size": size, "first_seen": row.get("first_seen"), "imphash": row.get("imphash"),
                             "file_name": row.get("file_name"), "code_sign": bool(row.get("code_sign")),
                             "tags": row.get("tags") or [], "source": "mb_" + label})
        time.sleep(args.sleep)
    fam = collections.Counter(r["family"] for r in selected)
    print(f"\nselected {len(selected)} new PE samples ({refused} evaluation hashes refused); "
          f"top signatures: {fam.most_common(12)}", file=sys.stderr)
    selected = selected[: args.max_download]
    if args.index_only:
        with index_path.open("a") as fh:
            for row in selected:
                fh.write(json.dumps({**row, "downloaded": False}) + "\n")
        return
    downloaded = failed = 0
    with index_path.open("a") as fh:
        for i, row in enumerate(selected, 1):
            target = archives / f"{row['sha256']}.zip"
            if not target.exists():
                try:
                    blob = api({"query": "get_file", "sha256_hash": row["sha256"]}, key)
                except Exception as e:
                    print(f"  download error {row['sha256'][:12]}: {e}", file=sys.stderr); failed += 1; continue
                if not isinstance(blob, bytes):
                    failed += 1; continue
                target.write_bytes(blob); target.chmod(0o600)
                time.sleep(args.sleep)
            downloaded += 1
            fh.write(json.dumps({**row, "downloaded": True, "archive": str(target.relative_to(args.out))}) + "\n")
            fh.flush()
            if i % 50 == 0:
                print(f"  {i}/{len(selected)} downloaded={downloaded} failed={failed}", file=sys.stderr)
    print(f"\ndownloaded {downloaded}, failed {failed}, into {archives}", file=sys.stderr)
    print("Archives are password-protected malware. Never extract to a Windows-reachable path; never execute.", file=sys.stderr)


if __name__ == "__main__":
    main()
