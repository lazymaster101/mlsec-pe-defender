#!/usr/bin/env python3
"""Turn EMBER 2018 JSONL into an NFS-schema dataset with a temporal split.

EMBER's per-sample JSON is the *same* shape ``JSONAttributeExtractor`` consumes in
``train_classifier.py``, so records convert without approximation -- including the
two quirks the trained model depends on: the swapped ``libraries``/``functions``
fields and their space padding.

Split is chronological on EMBER's ``appeared`` month, never random, so that
measured TPR reflects drift instead of leakage (threat model sections 5 and 6.1).

    python build_dataset.py --ember RAW/ember2018 --out work/dataset --cutoff 2018-08

Rows stream straight to disk; the trainer subsamples, so nothing here caps counts.
"""
from __future__ import annotations

import argparse
import collections
import json
import pathlib
import sys

# Field order must match defender/model.py and the trained schema.
NUMERICAL = [
    "virtual_size", "has_debug", "imports", "exports", "has_relocations",
    "has_resources", "has_signature", "has_tls", "symbols", "timestamp",
    "numberof_sections", "major_image_version", "minor_image_version",
    "major_linker_version", "minor_linker_version", "major_operating_system_version",
    "minor_operating_system_version", "major_subsystem_version",
    "minor_subsystem_version", "sizeof_code", "sizeof_headers", "sizeof_heap_commit",
]
OPTIONAL_FIELDS = [
    "major_image_version", "minor_image_version", "major_linker_version",
    "minor_linker_version", "major_operating_system_version",
    "minor_operating_system_version", "major_subsystem_version",
    "minor_subsystem_version", "sizeof_code", "sizeof_headers", "sizeof_heap_commit",
]


def to_attributes(record: dict) -> dict | None:
    """Reproduce JSONAttributeExtractor.extract() exactly."""
    try:
        general, header = record["general"], record["header"]
        coff, optional = header["coff"], header["optional"]
        attributes = {
            "virtual_size": general["vsize"], "has_debug": general["has_debug"],
            "imports": general["imports"], "exports": general["exports"],
            "has_relocations": general["has_relocations"],
            "has_resources": general["has_resources"],
            "has_signature": general["has_signature"], "has_tls": general["has_tls"],
            "symbols": general["symbols"], "timestamp": coff["timestamp"],
            "machine": coff["machine"],
            "numberof_sections": len(record["section"]["sections"]),
            "characteristics_list": " ".join(coff["characteristics"]),
            "dll_characteristics_list": " ".join(optional["dll_characteristics"]),
            "magic": optional["magic"],
        }
        for field in OPTIONAL_FIELDS:
            attributes[field] = optional[field]
        # The trainer stores imported FUNCTION names under 'libraries' and LIBRARY
        # names under 'functions', both space-padded. The token pattern needs the
        # padding, so this is load-bearing, not cosmetic.
        imports = record["imports"]
        attributes["libraries"] = " {} ".format(
            " ".join(item for sublist in imports.values() for item in sublist))
        attributes["functions"] = " {} ".format(" ".join(imports.keys()))
        attributes["exports_list"] = " ".join(record["exports"])
    except (KeyError, TypeError):
        return None
    return attributes


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--ember", type=pathlib.Path, required=True)
    parser.add_argument("--out", type=pathlib.Path, required=True)
    parser.add_argument("--cutoff", default="2018-08",
                        help="train on months < cutoff, test on months >= cutoff")
    parser.add_argument("--seed", type=int, default=20260919)
    args = parser.parse_args()

    sources = sorted(args.ember.glob("train_features_*.jsonl")) + \
              sorted(args.ember.glob("test_features*.jsonl"))
    if not sources:
        raise SystemExit(f"No EMBER JSONL under {args.ember}")
    args.out.mkdir(parents=True, exist_ok=True)

    seen: set[str] = set()
    months: collections.Counter = collections.Counter()
    stats = collections.Counter()
    counts = {"train": collections.Counter(), "test": collections.Counter()}

    # Stream straight to disk. Holding ~1.1M converted records in memory costs
    # several GB and buys nothing; the trainer subsamples while streaming.
    handles = {name: (args.out / f"{name}.jsonl").open("w") for name in ("train", "test")}
    try:
        for source in sources:
            print(f"reading {source.name}", file=sys.stderr, flush=True)
            with source.open() as stream:
                for line in stream:
                    try:
                        record = json.loads(line)
                    except ValueError:
                        stats["bad_json"] += 1
                        continue
                    label = record.get("label", -1)
                    if label not in (0, 1):
                        stats["unlabeled_dropped"] += 1   # EMBER's ambiguous band
                        continue
                    sha = record.get("sha256")
                    if not sha or sha in seen:
                        stats["duplicate_dropped"] += 1
                        continue
                    attributes = to_attributes(record)
                    if attributes is None:
                        stats["unparseable_dropped"] += 1
                        continue
                    seen.add(sha)
                    appeared = record.get("appeared", "")
                    months[appeared] += 1
                    split = "train" if appeared < args.cutoff else "test"
                    handles[split].write(json.dumps(
                        {"sha256": sha, "appeared": appeared, "label": label,
                         "attributes": attributes}) + "\n")
                    counts[split][label] += 1
                    stats[f"kept_label{label}"] += 1
    finally:
        for handle in handles.values():
            handle.close()

    for name in ("train", "test"):
        total = sum(counts[name].values())
        print(f"{name:5s}: {total:>7,} rows  benign={counts[name][0]:>7,} "
              f"malicious={counts[name][1]:>7,}", file=sys.stderr)

    manifest = {
        "source": "EMBER 2018 (ember_dataset_2018_2)",
        "cutoff": args.cutoff, "seed": args.seed,
        "split": "temporal on 'appeared'; train < cutoff <= test",
        "counts": {name: dict(counts[name]) for name in counts},
        "pipeline_stats": dict(stats),
        "months": dict(sorted(months.items())),
    }
    (args.out / "manifest.json").write_text(json.dumps(manifest, indent=2, default=int) + "\n")
    print(json.dumps(dict(stats), indent=2), file=sys.stderr)


if __name__ == "__main__":
    main()
