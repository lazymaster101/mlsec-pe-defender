#!/usr/bin/env python3
"""Harvest real benign PE binaries from NuGet.org (.nupkg files bundle actual DLLs,
unlike Chocolatey which ships install scripts). Populates dataset/goodware alongside
the Chocolatey corpus so the live (lief-0.17) benign set is large enough to balance
the live malware set and break the extraction-pipeline confound.

Grabs both managed (lib/) and native (runtimes/**/native/) PEs; dedups by sha256.

    python collect_nuget.py --out dataset/goodware --pages 40 --max-per-package 15
"""
from __future__ import annotations
import argparse, hashlib, io, json, pathlib, ssl, sys, time
import urllib.parse, urllib.request, zipfile

SEARCH = "https://azuresearch-usnc.nuget.org/query"
FLAT = "https://api.nuget.org/v3-flatcontainer"
PE_SUFFIXES = (".dll", ".exe")
try:
    import certifi
    _SSL = ssl.create_default_context(cafile=certifi.where())
except ImportError:
    _SSL = ssl.create_default_context()


def fetch(url, timeout=120):
    req = urllib.request.Request(url, headers={"User-Agent": "dataset-builder/1.0",
                                               "Accept": "application/json,*/*;q=0.8"})
    with urllib.request.urlopen(req, timeout=timeout, context=_SSL) as r:
        return r.read()


def list_packages(pages, per_page=100):
    """Page the NuGet search service (broad terms) for popular packages."""
    terms = ["", "core", "system", "microsoft", "extensions", "client", "aws",
             "google", "azure", "native", "windows", "sql", "json", "logging"]
    seen, out = set(), []
    for term in terms:
        for skip in range(0, pages * per_page, per_page):
            url = f"{SEARCH}?q={urllib.parse.quote(term)}&take={per_page}&skip={skip}&prerelease=false"
            try:
                data = json.loads(fetch(url))
            except Exception as e:
                print(f"  search '{term}' skip {skip}: {e}", file=sys.stderr); continue
            rows = data.get("data", [])
            if not rows:
                break
            for p in rows:
                pid = p["id"].lower(); ver = str(p["version"]).lower()
                if pid in seen:
                    continue
                seen.add(pid)
                out.append((pid, ver, p.get("totalDownloads", 0)))
            if len(out) >= pages * per_page:
                break
        if len(out) >= pages * per_page:
            break
    return out


def extract_pes(nupkg_bytes, max_bytes, cap):
    out = []
    try:
        zf = zipfile.ZipFile(io.BytesIO(nupkg_bytes))
    except Exception:
        return out
    for name in zf.namelist():
        low = name.lower()
        if not low.endswith(PE_SUFFIXES):
            continue
        if not (low.startswith("lib/") or "/native/" in low or low.startswith("runtimes/")):
            continue
        try:
            data = zf.read(name)
        except Exception:
            continue
        if 2 <= len(data) <= max_bytes and data[:2] == b"MZ":
            out.append((name, data))
        if len(out) >= cap:
            break
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=pathlib.Path, default=pathlib.Path("dataset/goodware"))
    ap.add_argument("--pages", type=int, default=40)
    ap.add_argument("--max-per-package", type=int, default=15)
    ap.add_argument("--max-bytes", type=int, default=32 * 1024 * 1024)
    ap.add_argument("--target", type=int, default=4000, help="stop after this many new PEs")
    ap.add_argument("--sleep", type=float, default=0.05)
    args = ap.parse_args()

    binaries = args.out / "pe"; binaries.mkdir(parents=True, exist_ok=True)
    index_path = args.out / "index.jsonl"
    have = set()
    if index_path.exists():
        for line in index_path.open():
            try: have.add(json.loads(line)["sha256"])
            except Exception: pass
    print(f"have {len(have)} PEs; listing NuGet packages...", file=sys.stderr)
    pkgs = list_packages(args.pages)
    print(f"got {len(pkgs)} packages; downloading", file=sys.stderr)

    kept = skipped = 0
    with index_path.open("a") as stream:
        for i, (pid, ver, downloads) in enumerate(pkgs, 1):
            url = f"{FLAT}/{pid}/{ver}/{pid}.{ver}.nupkg"
            try:
                blob = fetch(url)
            except Exception:
                continue
            for name, data in extract_pes(blob, args.max_bytes, args.max_per_package):
                digest = hashlib.sha256(data).hexdigest()
                if digest in have:
                    skipped += 1; continue
                have.add(digest)
                (binaries / f"{digest}.bin").write_bytes(data)
                stream.write(json.dumps({"sha256": digest, "bytes": len(data),
                    "source": "nuget", "package": pid, "package_version": ver,
                    "package_downloads": downloads, "member": name}) + "\n")
                kept += 1
            stream.flush()
            if i % 25 == 0:
                print(f"  {i}/{len(pkgs)} pkgs, {kept} PEs kept, {skipped} dupes", file=sys.stderr)
            if kept >= args.target:
                print(f"  reached target {args.target}", file=sys.stderr); break
            time.sleep(args.sleep)
    print(f"\nkept {kept} new PE files (total corpus now {len(have)})", file=sys.stderr)


if __name__ == "__main__":
    main()
