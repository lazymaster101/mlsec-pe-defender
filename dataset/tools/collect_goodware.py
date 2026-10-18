#!/usr/bin/env python3
"""Harvest current, real Windows PE goodware from the Chocolatey community feed.

Recent malware needs recent benign software to sit beside it. Pairing 2026 malware
against 2018 benign files would let a model separate the classes on era artefacts
(linker versions, timestamps) rather than on maliciousness -- the sampling bias the
threat model rules out in section 6.

Packages are ranked by download count, so the result skews toward software people
actually run, which is the population whose false positives matter. Binaries are
extracted from the .nupkg; nothing is installed or executed.

    python collect_goodware.py --out dataset/goodware --packages 250
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import pathlib
import ssl
import sys
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ElementTree
import zipfile

FEED = "https://community.chocolatey.org/api/v2/"
ATOM = "{http://www.w3.org/2005/Atom}"
DATA = "{http://schemas.microsoft.com/ado/2007/08/dataservices}"
META = "{http://schemas.microsoft.com/ado/2007/08/dataservices/metadata}"
PE_SUFFIXES = (".exe", ".dll", ".sys", ".ocx", ".cpl")


def _ssl_context() -> ssl.SSLContext:
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        return ssl.create_default_context()


_SSL = _ssl_context()


def fetch(url: str, timeout: int = 120) -> bytes:
    # The feed answers 406 without an explicit Accept for the Atom media type.
    request = urllib.request.Request(url, headers={
        "User-Agent": "Mozilla/5.0 (compatible; dataset-builder/1.0)",
        "Accept": "application/atom+xml,application/xml;q=0.9,*/*;q=0.8",
    })
    with urllib.request.urlopen(request, timeout=timeout, context=_SSL) as response:
        return response.read()


def list_packages(count: int, page: int = 100) -> list[dict]:
    """Page the OData feed ordered by download count."""
    packages: list[dict] = []
    seen: set[str] = set()
    for skip in range(0, count * 2, page):
        # quote_via=quote so the space in "$orderby" becomes %20, not "+";
        # a literal space or a "+" both make the feed answer 406.
        query = urllib.parse.urlencode({
            "$filter": "IsLatestVersion", "$orderby": "DownloadCount desc",
            "$top": page, "$skip": skip,
        }, safe="$", quote_via=urllib.parse.quote)
        try:
            body = fetch(f"{FEED}Packages()?{query}")
        except Exception as error:
            print(f"  feed page skip={skip} failed: {error}", file=sys.stderr)
            break
        root = ElementTree.fromstring(body)
        entries = root.findall(f"{ATOM}entry")
        if not entries:
            break
        for entry in entries:
            properties = entry.find(f"{ATOM}content/../{META}properties")
            if properties is None:
                properties = entry.find(f".//{META}properties")
            identifier = entry.findtext(f"{ATOM}title")
            if not identifier or identifier in seen:
                continue
            seen.add(identifier)
            version = properties.findtext(f"{DATA}Version") if properties is not None else None
            downloads = properties.findtext(f"{DATA}DownloadCount") if properties is not None else "0"
            packages.append({"id": identifier, "version": version,
                             "downloads": int(downloads or 0)})
        print(f"  listed {len(packages)} packages", file=sys.stderr)
        if len(packages) >= count:
            break
    return packages[:count]


def extract_pes(blob: bytes, max_bytes: int) -> list[tuple[str, bytes]]:
    found = []
    try:
        archive = zipfile.ZipFile(io.BytesIO(blob))
    except zipfile.BadZipFile:
        return found
    for info in archive.infolist():
        if info.file_size > max_bytes or not info.filename.lower().endswith(PE_SUFFIXES):
            continue
        try:
            data = archive.read(info)
        except Exception:
            continue
        if data[:2] == b"MZ":                    # skip .NET stubs that are not PEs
            found.append((info.filename, data))
    return found


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=pathlib.Path, required=True)
    parser.add_argument("--packages", type=int, default=250)
    parser.add_argument("--max-per-package", type=int, default=6)
    parser.add_argument("--max-bytes", type=int, default=32 * 1024 * 1024)
    parser.add_argument("--sleep", type=float, default=0.3)
    args = parser.parse_args()

    binaries = args.out / "pe"
    binaries.mkdir(parents=True, exist_ok=True)
    index_path = args.out / "index.jsonl"
    have = set()
    if index_path.exists():
        with index_path.open() as stream:
            for line in stream:
                try:
                    have.add(json.loads(line)["sha256"])
                except (ValueError, KeyError):
                    continue

    print(f"listing top {args.packages} Chocolatey packages...", file=sys.stderr)
    packages = list_packages(args.packages)
    print(f"got {len(packages)} packages; downloading", file=sys.stderr)

    kept = skipped = 0
    with index_path.open("a") as stream:
        for number, package in enumerate(packages, 1):
            url = f"{FEED}package/{urllib.parse.quote(package['id'])}"
            try:
                blob = fetch(url)
            except Exception as error:
                print(f"  {package['id']}: {error}", file=sys.stderr)
                continue
            extracted = extract_pes(blob, args.max_bytes)[:args.max_per_package]
            for name, data in extracted:
                digest = hashlib.sha256(data).hexdigest()
                if digest in have:
                    skipped += 1
                    continue
                have.add(digest)
                (binaries / f"{digest}.bin").write_bytes(data)
                stream.write(json.dumps({
                    "sha256": digest, "bytes": len(data), "source": "chocolatey",
                    "package": package["id"], "package_version": package["version"],
                    "package_downloads": package["downloads"], "member": name,
                }) + "\n")
                kept += 1
            stream.flush()
            if number % 25 == 0:
                print(f"  {number}/{len(packages)} packages, {kept} PEs kept, "
                      f"{skipped} dupes", file=sys.stderr)
            time.sleep(args.sleep)
    print(f"\nkept {kept} unique PE files in {binaries}", file=sys.stderr)


if __name__ == "__main__":
    main()
