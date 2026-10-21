#!/usr/bin/env python3
"""Split the recent set into train/test portions for an honest recent-threat test.

Default (as used for rf_adv in September 2026): family-stratified RANDOM split, test_frac of
each malware family and of goodware held out. The review of 2026-09-21 (finding 6) showed
what that split cannot establish: it is not chronological, so it says nothing about
forward-in-time generalization; it keeps feature-identical repacks on both sides (84/433
recent_test malware rows had attributes identical to a recent_train row); it drops
unparseable rows, which the server scores as 1; and the 140 benign train rows must never be
pooled with the 60 held-out benign rows when a false-positive rate is reported.

Options that fix each point (all off by default so the historical split stays reproducible):
  --group-duplicates   rows with identical attribute dicts go to the SAME side
  --temporal           within each family (and for goodware), the most recent test_frac by
                       'appeared' date go to test (forward-in-time evaluation)
  --keep-unparseable   unparseable rows go to the TEST side with attributes=None (scored 1)

Re-splitting invalidates any model trained on the previous recent_train (rf_adv): retrain
before reporting numbers on a new split.
"""
import argparse, collections, hashlib, json, pathlib, random

parser = argparse.ArgumentParser()
parser.add_argument("--recent", type=pathlib.Path, default="dataset/work/recent.jsonl")
parser.add_argument("--out-dir", type=pathlib.Path, default="dataset/work")
parser.add_argument("--test-frac", type=float, default=0.3)
parser.add_argument("--seed", type=int, default=20260919)
parser.add_argument("--group-duplicates", action="store_true")
parser.add_argument("--temporal", action="store_true")
parser.add_argument("--keep-unparseable", action="store_true")
args = parser.parse_args()

rows = [json.loads(l) for l in args.recent.open() if l.strip()]
unparseable = [r for r in rows if r["attributes"] is None]
rows = [r for r in rows if r["attributes"] is not None]   # unparseable -> not trainable
rng = random.Random(args.seed)


def feature_key(r):
    return hashlib.sha256(json.dumps(r["attributes"], sort_keys=True).encode()).hexdigest()


# Group malware by family, goodware as one group; hold out test_frac of each.
groups = collections.defaultdict(list)
for r in rows:
    key = ("mal:" + (r["meta"].get("family") or "unknown")) if r["label"] == 1 else "benign"
    groups[key].append(r)

train, test = [], []
for key, items in groups.items():
    # units are either single rows or clusters of feature-identical rows
    if args.group_duplicates:
        clusters = collections.defaultdict(list)
        for r in items:
            clusters[feature_key(r)].append(r)
        units = list(clusters.values())
    else:
        units = [[r] for r in items]
    if args.temporal:
        units.sort(key=lambda u: max(x.get("appeared", "") for x in u))   # oldest first
    else:
        rng.shuffle(units)
    n_rows = sum(len(u) for u in units)
    want = max(1, int(n_rows * args.test_frac)) if n_rows > 1 else 0
    got, held = 0, []
    # temporal: take from the NEWEST end; random: from the front of the shuffle
    order = list(reversed(units)) if args.temporal else units
    for u in order:
        if got >= want:
            train.extend(u)
        else:
            held.extend(u); got += len(u)
    test.extend(held)
if args.keep_unparseable:
    test.extend(unparseable)

for name, part in (("recent_train", train), ("recent_test", test)):
    path = args.out_dir / f"{name}.jsonl"
    with path.open("w") as fh:
        for r in part:
            fh.write(json.dumps({"sha256": r["sha256"], "label": r["label"],
                                 "appeared": r.get("appeared", ""),
                                 "attributes": r["attributes"], "meta": r.get("meta", {})}) + "\n")
    lab = collections.Counter(r["label"] for r in part)
    print(f"  {name}: {len(part):,}  malicious={lab[1]} benign={lab[0]}")
if args.group_duplicates:
    tr = {feature_key(r) for r in train if r["attributes"] is not None}
    leak = sum(1 for r in test if r["attributes"] is not None and feature_key(r) in tr)
    print(f"  feature-identical test rows with a train twin: {leak}")
if args.temporal:
    def span(part):
        d = sorted(r.get("appeared", "") for r in part if r.get("appeared"))
        return (d[0], d[-1]) if d else ("", "")
    print(f"  appeared: train {span(train)}  test {span(test)}")
print(f"  unparseable rows: {len(unparseable)} ({'in test' if args.keep_unparseable else 'dropped'})")

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
