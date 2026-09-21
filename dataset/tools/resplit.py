#!/usr/bin/env python3
"""Re-cut an existing NFS-schema split at a new month, without re-reading EMBER."""
import collections, json, pathlib, sys

src, dst, cutoff = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), sys.argv[3]
dst.mkdir(parents=True, exist_ok=True)
counts = {"train": collections.Counter(), "test": collections.Counter()}
months = {"train": collections.Counter(), "test": collections.Counter()}
out = {n: (dst / f"{n}.jsonl").open("w") for n in ("train", "test")}
try:
    for name in ("train", "test"):
        path = src / f"{name}.jsonl"
        if not path.exists():
            continue
        with path.open() as stream:
            for line in stream:
                row = json.loads(line)
                split = "train" if row["appeared"] < cutoff else "test"
                out[split].write(line)
                counts[split][row["label"]] += 1
                months[split][row["appeared"]] += 1
finally:
    for handle in out.values():
        handle.close()
for name in ("train", "test"):
    span = sorted(months[name])
    print(f"{name:5s}: {sum(counts[name].values()):>7,} rows  benign={counts[name][0]:>7,} "
          f"malicious={counts[name][1]:>7,}  months {span[0]}..{span[-1]}")
(dst / "manifest.json").write_text(json.dumps({
    "source": "EMBER 2018 (ember_dataset_2018_2)",
    "cutoff": cutoff,
    "split": "temporal on 'appeared'; train < cutoff <= test. "
             "cutoff 2018-11 reproduces EMBER's official benchmark split.",
    "counts": {n: dict(counts[n]) for n in counts},
    "months": {n: dict(sorted(months[n].items())) for n in months},
}, indent=2) + "\n")
