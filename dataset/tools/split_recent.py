#!/usr/bin/env python3
"""Family-stratified split of the recent set into train/test portions.

Holds out a fraction of each malware family (and of goodware) for an honest
recent-threat test, and emits the remainder as an augmentation file to append to
EMBER training. Answers directly: does adding the collected recent samples improve
detection of *other* recent samples the model never saw?
"""
import argparse, collections, json, pathlib, random

parser = argparse.ArgumentParser()
parser.add_argument("--recent", type=pathlib.Path, default="dataset/work/recent.jsonl")
parser.add_argument("--out-dir", type=pathlib.Path, default="dataset/work")
parser.add_argument("--test-frac", type=float, default=0.3)
parser.add_argument("--seed", type=int, default=20260919)
args = parser.parse_args()

rows = [json.loads(l) for l in args.recent.open() if l.strip()]
rows = [r for r in rows if r["attributes"] is not None]   # unparseable -> not trainable
rng = random.Random(args.seed)

# Group malware by family, goodware as one group; hold out test_frac of each.
groups = collections.defaultdict(list)
for r in rows:
    key = ("mal:" + (r["meta"].get("family") or "unknown")) if r["label"] == 1 else "benign"
    groups[key].append(r)

train, test = [], []
for key, items in groups.items():
    rng.shuffle(items)
    k = max(1, int(len(items) * args.test_frac)) if len(items) > 1 else 0
    test.extend(items[:k]); train.extend(items[k:])

for name, part in (("recent_train", train), ("recent_test", test)):
    path = args.out_dir / f"{name}.jsonl"
    with path.open("w") as fh:
        for r in part:
            fh.write(json.dumps({"sha256": r["sha256"], "label": r["label"],
                                 "appeared": r.get("appeared", ""),
                                 "attributes": r["attributes"], "meta": r.get("meta", {})}) + "\n")
    lab = collections.Counter(r["label"] for r in part)
    print(f"  {name}: {len(part):,}  malicious={lab[1]} benign={lab[0]}")

# Combined EMBER-train + recent-train for the augmented model.
combined = args.out_dir / "ember_plus_recent_train.jsonl"
ember = args.out_dir / "ember_official" / "train.jsonl"
n = 0
with combined.open("w") as out:
    with ember.open() as fh:
        for line in fh:
            out.write(line); n += 1
    for r in train:
        out.write(json.dumps({"sha256": r["sha256"], "label": r["label"],
                              "appeared": r.get("appeared", ""),
                              "attributes": r["attributes"]}) + "\n")
print(f"  ember_plus_recent_train: {n:,} EMBER + {len(train):,} recent = {n + len(train):,}")
