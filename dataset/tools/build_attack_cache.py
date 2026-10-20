#!/usr/bin/env python3
"""EMBER-2381 vectors of problem-space ATTACK VARIANTS of the training malware, for
attack-aware fine-tuning (Lucas et al. 2023: train on the attack, not on augmentation).

Variants are produced IN MEMORY by the same functions the robustness suite uses
(eval_robustness.attack), so training and evaluation share one mechanism, but with a
DIFFERENT donor pool: goodware2 development-pool EXEs (never holdout/excluded products).
goodware2 is hash-deduplicated against the `goodware` corpus the suite draws its donors
from, so no evaluation donor bytes are ever seen in training.

Trained mechanisms: overlay_1m, overlay_4m, strings_10k, section_inject.
Held out of training (transfer test): overlay_64k, header_copy, cert_blob.

Nothing is written to disk except feature vectors and metadata. Nothing is executed.
Output: dataset/work/live_cache/X_malware_adv.npy, meta_malware_adv.jsonl
"""
from __future__ import annotations
import json, multiprocessing as mp, os, pathlib, random, sys, time
import numpy as np

ROOT = pathlib.Path(__file__).resolve().parents[2]
C = ROOT / "dataset/work/live_cache"
EXP = ROOT / "dataset/work/exp"
ATTACKS = ("overlay_1m", "overlay_4m", "strings_10k", "section_inject")
_W = {}


def _init(donor_paths):
    sys.path.insert(0, str(ROOT / "defender_product")); sys.path.insert(0, str(ROOT / "dataset/tools"))
    os.environ.setdefault("OMP_NUM_THREADS", "1")
    import lief
    lief.logging.disable()
    from defender import ember_features, ember_compat  # noqa: F401  (serving extractor, lean strings)
    import eval_robustness as R
    R._S["lief"] = lief
    R._S["donors"] = [pathlib.Path(p).read_bytes() for p in donor_paths]
    R._S["signed"] = []          # cert_blob is deliberately NOT trained
    _W["ext"] = ember_features.PEFeatureExtractor(2, print_feature_warning=False)
    _W["attack"] = R.attack


def work(d):
    import pyzipper
    with pyzipper.AESZipFile(ROOT / f"dataset/quarantine/archives/{d['sha256']}.zip") as a:
        a.setpassword(b"infected"); b = a.read(a.infolist()[0])
    rng = random.Random("v41:" + d["sha256"])
    out = []
    for name in ATTACKS:
        try:
            x = _W["attack"](name, b, rng)
            if x is None:
                continue
            v = np.asarray(_W["ext"].feature_vector(x), dtype=np.float32)
        except Exception as e:
            out.append((None, {"orig": d["sha256"], "attack": name, "err": repr(e)[:100]})); continue
        out.append((v, {"orig": d["sha256"], "attack": name, "group": d["group"], "size": len(x),
                        "is_dll": bool(d["pe"].get("is_dll")), "is_dotnet": bool(d["pe"].get("is_dotnet"))}))
    return out


def main():
    sys.path.insert(0, str(ROOT / "dataset/tools"))
    from train_v4 import norm_group
    banned = {norm_group(g) for g in json.load(open(EXP / "v4_holdout_groups.json")) + json.load(open(EXP / "v4_excluded_groups.json"))}
    g2 = [json.loads(l) for l in open(C / "meta_goodware2.jsonl")]
    pool = [d for d in g2 if norm_group(d["group"]) not in banned and not d["pe"].get("is_dll")
            and not d["pe"].get("is_dotnet") and 50_000 <= d["size"] <= 8 << 20]
    donors = random.Random(11).sample(pool, 40)
    donor_paths = [str(ROOT / f"dataset/goodware2/pe/{d['sha256']}.bin") for d in donors]
    json.dump([d["sha256"] for d in donors], open(EXP / "v41_train_donors.json", "w"))
    mal = [json.loads(l) for l in open(C / "meta_malware.jsonl")]
    print(f"{len(mal)} malware x {len(ATTACKS)} attacks; {len(donors)} training donors from {len({d['group'] for d in donors})} dev products", flush=True)
    t0 = time.time(); X, meta, errs = [], [], 0
    with mp.Pool(6, initializer=_init, initargs=(donor_paths,), maxtasksperchild=100) as pool_:
        for i, res in enumerate(pool_.imap(work, mal, chunksize=2)):
            for v, m in res:
                if v is None:
                    errs += 1; continue
                X.append(v); meta.append(m)
            if (i + 1) % 200 == 0:
                print(f"  {i+1}/{len(mal)} ({len(X)} variants, {errs} errors) {time.time()-t0:.0f}s", flush=True)
    np.save(C / "X_malware_adv.npy", np.stack(X).astype(np.float32))
    with open(C / "meta_malware_adv.jsonl", "w") as fh:
        for m in meta:
            fh.write(json.dumps(m) + "\n")
    print(f"done: {len(X)} variant vectors, {errs} errors, {time.time()-t0:.0f}s -> {C}/X_malware_adv.npy", flush=True)


if __name__ == "__main__":
    main()
