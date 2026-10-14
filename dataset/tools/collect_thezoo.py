#!/usr/bin/env python3
"""Collect Win32/W32 malware from theZoo (github.com/ytisf/theZoo) as raw PE files.

Clones theZoo (shallow, sparse: only malware/Binaries), keeps folders whose name
starts with "Win32" or "W32" (case-insensitive), decrypts each archive with the
password "infected", and writes only the members that are PE files (MZ header)
to --out as <sha256>.bin (or .exe/.dll with --ext auto) so tools/evaluate.py can score them directly.

These are LIVE malware. Run in a VM / isolated Linux host. Outputs are 0600 with no
execute bit and a .bin extension; nothing here executes a sample.

    pip install pyzipper
    python collect_thezoo.py --out ~/eval_data/malicious_thezoo
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import pathlib
import subprocess
import sys

import pyzipper

REPO = "https://github.com/ytisf/theZoo.git"
PASSWORD = b"infected"
PREFIXES = ("win32", "w32")
MAX_NESTING = 2          # theZoo occasionally zips a zip


def clone(dest: pathlib.Path) -> pathlib.Path:
    if (dest / ".git").exists():
        print(f"using existing clone at {dest}", file=sys.stderr)
    else:
        dest.parent.mkdir(parents=True, exist_ok=True)
        run = lambda *a: subprocess.run(a, check=True)
        run("git", "clone", "--depth", "1", "--filter=blob:none", "--sparse", REPO, str(dest))
        run("git", "-C", str(dest), "sparse-checkout", "set", "malware/Binaries")
    return dest / "malware" / "Binaries"


def members(blob: bytes, depth: int = 0):
    """Yield (name, bytes) for every file inside an 'infected' zip, recursing once or twice."""
    try:
        archive = pyzipper.AESZipFile(io.BytesIO(blob))
        archive.setpassword(PASSWORD)
        names = [n for n in archive.namelist() if not n.endswith("/")]
    except Exception as error:
        print(f"    not a readable zip: {error}", file=sys.stderr)
        return
    for name in names:
        try:
            data = archive.read(name)
        except Exception as error:
            print(f"    {name}: {error}", file=sys.stderr)
            continue
        if data[:2] == b"PK" and depth < MAX_NESTING:
            yield from members(data, depth + 1)
        else:
            yield name, data


def pe_suffix(data: bytes) -> str:
    """'.dll' if the PE header sets IMAGE_FILE_DLL, else '.exe'."""
    try:
        pe = int.from_bytes(data[0x3C:0x40], "little")
        if data[pe:pe + 4] == b"PE\0\0":
            flags = int.from_bytes(data[pe + 22:pe + 24], "little")
            return ".dll" if flags & 0x2000 else ".exe"
    except Exception:
        pass
    return ".exe"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=pathlib.Path, required=True)
    parser.add_argument("--clone-dir", type=pathlib.Path, default=pathlib.Path("thezoo_repo"),
                        help="where to clone theZoo (reused if it already exists)")
    parser.add_argument("--ext", choices=("bin", "auto"), default="bin",
                        help="'auto' names files .exe/.dll from the PE header; 'bin' (default) "
                             "is safer because nothing looks double-clickable")
    parser.add_argument("--keep-non-pe", action="store_true",
                        help="also keep members without an MZ header")
    args = parser.parse_args()

    binaries = clone(args.clone_dir)
    if not binaries.is_dir():
        raise SystemExit(f"{binaries} not found; clone/sparse-checkout failed")

    folders = sorted(p for p in binaries.iterdir()
                     if p.is_dir() and p.name.lower().startswith(PREFIXES))
    print(f"{len(folders)} Win32/W32 folders", file=sys.stderr)

    args.out.mkdir(parents=True, exist_ok=True)
    index, kept, skipped = [], 0, 0
    for folder in folders:
        for archive in sorted(folder.glob("*.zip")):
            for name, data in members(archive.read_bytes()):
                if data[:2] != b"MZ" and not args.keep_non_pe:
                    skipped += 1
                    continue
                sha = hashlib.sha256(data).hexdigest()
                suffix = pe_suffix(data) if args.ext == "auto" else ".bin"
                target = args.out / f"{sha}{suffix}"
                if not target.exists():
                    target.write_bytes(data)
                    target.chmod(0o600)
                kept += 1
                index.append({"sha256": sha, "family": folder.name,
                              "member": name, "size": len(data)})
        print(f"  {folder.name}", file=sys.stderr)

    (args.out / "index.json").write_text(json.dumps(index, indent=2) + "\n")
    print(f"\nkept {kept} files ({len(index)} indexed), skipped {skipped} non-PE, into {args.out}",
          file=sys.stderr)
    print("Index is index.json; delete it (or point evaluate.py at a subdir) if you want "
          "only samples scored.", file=sys.stderr)


if __name__ == "__main__":
    main()
