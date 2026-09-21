#!/usr/bin/env python3
"""Extract NFS-schema attributes from collected PE files into labelled JSONL.

Handles both collections: quarantined malware, which stays in its AES-encrypted
archive and is decrypted only in memory, and harvested goodware, which is plain
on disk. Nothing is written out in executable form and nothing is run.

Samples the parser rejects are kept with ``attributes: null`` and scored 1 by the
evaluator, matching the server. Dropping them would quietly flatter the numbers.

    python extract_pe.py --malware dataset/quarantine --goodware dataset/goodware \
                         --out dataset/work/recent.jsonl
"""
from __future__ import annotations

import argparse
import collections
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "defender_product"))
from defender import features as feature_extraction    # noqa: E402


def read_index(root: pathlib.Path) -> dict[str, dict]:
    index: dict[str, dict] = {}
    path = root / "index.jsonl"
    if path.exists():
        with path.open() as stream:
            for line in stream:
                try:
                    record = json.loads(line)
                    index[record["sha256"]] = record
                except (ValueError, KeyError):
                    continue
    return index


def read_sample(path: pathlib.Path) -> bytes:
    if path.suffix == ".zip":
        import pyzipper
        with pyzipper.AESZipFile(path) as archive:
            archive.setpassword(b"infected")
            return archive.read(archive.infolist()[0])
    return path.read_bytes()


def harvest(root: pathlib.Path, subdir: str, label: int, stats: collections.Counter):
    index = read_index(root)
    directory = root / subdir
    if not directory.is_dir():
        return
    for path in sorted(directory.iterdir()):
        if not path.is_file():
            continue
        digest = path.stem
        meta = index.get(digest, {})
        try:
            blob = read_sample(path)
        except Exception as error:
            stats["unreadable"] += 1
            print(f"  unreadable {path.name}: {error}", file=sys.stderr)
            continue
        try:
            attributes = feature_extraction.extract(blob, "training")
            stats[f"ok_label{label}"] += 1
        except Exception:
            attributes = None
            stats[f"unparseable_label{label}"] += 1
        yield {
            "sha256": digest, "label": label, "attributes": attributes,
            "bytes": len(blob),
            "appeared": (meta.get("first_seen") or "")[:7],
            "meta": {k: meta[k] for k in
                     ("family", "reported_signature", "first_seen", "file_type",
                      "package", "package_version", "source", "member")
                     if k in meta},
        }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--malware", type=pathlib.Path)
    parser.add_argument("--goodware", type=pathlib.Path)
    parser.add_argument("--out", type=pathlib.Path, required=True)
    args = parser.parse_args()

    stats: collections.Counter = collections.Counter()
    families: collections.Counter = collections.Counter()
    months: collections.Counter = collections.Counter()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    with args.out.open("w") as stream:
        for root, subdir, label in ((args.malware, "archives", 1),
                                    (args.goodware, "pe", 0)):
            if root is None:
                continue
            for row in harvest(root, subdir, label, stats):
                stream.write(json.dumps(row) + "\n")
                written += 1
                if label == 1:
                    families[row["meta"].get("family", "unknown")] += 1
                    months[row["appeared"]] += 1
    print(f"wrote {written:,} rows to {args.out}", file=sys.stderr)
    print(json.dumps(dict(stats), indent=2), file=sys.stderr)
    if families:
        print(f"malware families: {len(families)}", file=sys.stderr)
        for name, count in families.most_common(12):
            print(f"  {name:20s} {count}", file=sys.stderr)
        print(f"first-seen months: {dict(sorted(months.items()))}", file=sys.stderr)


if __name__ == "__main__":
    main()
