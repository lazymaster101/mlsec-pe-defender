#!/usr/bin/env python3
"""Harvest NATIVE Windows benign PEs from GitHub release .zip assets of popular
native (C/C++) OSS projects. NuGet gave mostly managed .NET DLLs; our malware is
native, so we need native benign to balance it and kill the native->malicious
shortcut. Uses `gh api` (authenticated) for release metadata, urllib for downloads.

    python collect_github.py --out dataset/goodware --target 1600
"""
from __future__ import annotations
import argparse, hashlib, io, json, pathlib, ssl, subprocess, sys, time
import urllib.request, zipfile

# Native-heavy projects whose Windows release assets are .zip (not .7z/.msi/installer).
REPOS = [
    "git-for-windows/git", "obsproject/obs-studio", "BtbN/FFmpeg-Builds",
    "notepad-plus-plus/notepad-plus-plus", "audacity/audacity", "aria2/aria2",
    "curl/curl", "PowerShell/PowerShell", "microsoft/PowerToys", "ShareX/ShareX",
    "mpv-player/mpv", "qbittorrent/qBittorrent", "FiloSottile/age", "jqlang/jq",
    "sharkdp/fd", "BurntSushi/ripgrep", "gyscos/zola", "wez/wezterm",
    "rust-lang/rust-analyzer", "cli/cli", "hashicorp/terraform", "prometheus/prometheus",
    "syncthing/syncthing", "restic/restic", "rclone/rclone", "yt-dlp/yt-dlp",
    "openssl/openssl", "libsdl-org/SDL", "GnuWin32/libarchive", "espressif/esp-idf",
]
try:
    import certifi
    _SSL = ssl.create_default_context(cafile=certifi.where())
except ImportError:
    _SSL = ssl.create_default_context()


def gh_releases(repo, per_repo_releases=2):
    try:
        out = subprocess.run(["gh", "api", f"repos/{repo}/releases?per_page={per_repo_releases}"],
                             capture_output=True, text=True, timeout=60)
        if out.returncode != 0:
            return []
        return json.loads(out.stdout)
    except Exception:
        return []


def download(url, timeout=300, cap=200 * 1024 * 1024):
    req = urllib.request.Request(url, headers={"User-Agent": "dataset-builder/1.0"})
    with urllib.request.urlopen(req, timeout=timeout, context=_SSL) as r:
        data = r.read(cap + 1)
    return data if len(data) <= cap else None


def win_zip_assets(rel):
    for a in rel.get("assets", []):
        name = a["name"].lower()
        if name.endswith(".zip") and not any(x in name for x in ("src", "source", "debug", "pdb", "linux", "mac", "arm")):
            if any(x in name for x in ("win", "x64", "64-bit", "windows")) or True:
                yield a["name"], a["browser_download_url"], a.get("size", 0)


def extract_native_pes(zip_bytes, cap, max_bytes=32 * 1024 * 1024):
    out = []
    try:
        zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
    except Exception:
        return out
    for n in zf.namelist():
        if not n.lower().endswith((".exe", ".dll", ".sys", ".ocx", ".cpl")):
            continue
        try:
            d = zf.read(n)
        except Exception:
            continue
        if 2 <= len(d) <= max_bytes and d[:2] == b"MZ":
            out.append((n, d))
        if len(out) >= cap:
            break
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=pathlib.Path, default=pathlib.Path("dataset/goodware"))
    ap.add_argument("--target", type=int, default=1600)
    ap.add_argument("--max-per-repo", type=int, default=250)
    args = ap.parse_args()
    binaries = args.out / "pe"; binaries.mkdir(parents=True, exist_ok=True)
    index_path = args.out / "index.jsonl"
    have = set()
    if index_path.exists():
        for line in index_path.open():
            try: have.add(json.loads(line)["sha256"])
            except Exception: pass
    print(f"have {len(have)} PEs; harvesting native PEs from {len(REPOS)} GitHub repos", file=sys.stderr)
    kept = 0
    with index_path.open("a") as stream:
        for repo in REPOS:
            if kept >= args.target:
                break
            repo_kept = 0
            for rel in gh_releases(repo):
                for aname, url, size in win_zip_assets(rel):
                    if size and size > 200 * 1024 * 1024:
                        continue
                    try:
                        blob = download(url)
                    except Exception:
                        continue
                    if not blob:
                        continue
                    for member, data in extract_native_pes(blob, args.max_per_repo - repo_kept):
                        digest = hashlib.sha256(data).hexdigest()
                        if digest in have:
                            continue
                        have.add(digest)
                        (binaries / f"{digest}.bin").write_bytes(data)
                        stream.write(json.dumps({"sha256": digest, "bytes": len(data),
                            "source": "github", "package": repo, "member": f"{aname}:{member}"}) + "\n")
                        kept += 1; repo_kept += 1
                    stream.flush()
                    if repo_kept >= args.max_per_repo:
                        break
                if repo_kept >= args.max_per_repo:
                    break
            print(f"  {repo}: +{repo_kept} native PEs (total new {kept})", file=sys.stderr)
    print(f"\nkept {kept} new native PE files", file=sys.stderr)


if __name__ == "__main__":
    main()
