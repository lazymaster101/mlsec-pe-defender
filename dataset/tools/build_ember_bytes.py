#!/usr/bin/env python3
"""Vectorize the PARSER-INDEPENDENT slice of EMBER-2381 for all labeled EMBER 2018 rows.

EMBER vector layout (v2): ByteHistogram 256 | ByteEntropyHistogram 256 | Strings 104 |
GeneralFileInfo 10 (first = raw file size) | Header | Section | Imports | Exports | DataDirs.
The first 616 dims plus raw file size (dim 616) are computed from the raw bytes with
numpy/regex only -- lief is never involved -- so they are IDENTICAL whether the row came
from the 2019 EMBER JSONL (lief 0.9) or from our live lief-0.17 serving extractor. A model
on this 617-dim slice can therefore mix EMBER 2018 with live-extracted recent samples
without the "extractor version => label" shortcut that sank the earlier mixed model.

Uses the serving code's own process_raw_features (submission/defender/ember_features.py).
Output: dataset/work/ember_bytes/{train,test}.npz with X (float32, N x 617), y, appeared.
"""
from __future__ import annotations
import json, multiprocessing as mp, pathlib, sys, time
import numpy as np

ROOT = pathlib.Path(__file__).resolve().parents[2]
RAW = ROOT / "dataset/raw/ember2018"
OUT = ROOT / "dataset/work/ember_bytes"
NDIM = 617


def vec(raw, fe):
    hist, bent, strs = fe
    return np.hstack([hist.process_raw_features(raw["histogram"]),
                      bent.process_raw_features(raw["byteentropy"]),
                      strs.process_raw_features(raw["strings"]),
                      np.float32(raw["general"]["size"])]).astype(np.float32)


def do_file(path: str):
    sys.path.insert(0, str(ROOT / "submission"))
    from defender import ember_features as ef
    fe = (ef.ByteHistogram(), ef.ByteEntropyHistogram(), ef.StringExtractor())
    X, y, ap = [], [], []
    t0 = time.time()
    with open(path) as fh:
        for line in fh:
            d = json.loads(line)
            if d["label"] not in (0, 1):
                continue
            X.append(vec(d, fe)); y.append(d["label"]); ap.append(d["appeared"])
    print(f"  {pathlib.Path(path).name}: {len(y)} labeled rows in {time.time()-t0:.0f}s", flush=True)
    return np.stack(X), np.array(y, dtype=np.int8), np.array(ap)


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    files = [str(RAW / f"train_features_{i}.jsonl") for i in range(6)] + [str(RAW / "test_features.jsonl")]
    with mp.Pool(7) as pool:
        res = pool.map(do_file, files)
    tr = res[:6]
    X = np.concatenate([r[0] for r in tr]); y = np.concatenate([r[1] for r in tr]); ap = np.concatenate([r[2] for r in tr])
    np.savez(OUT / "train.npz", X=X, y=y, appeared=ap)
    Xt, yt, apt = res[6]
    np.savez(OUT / "test.npz", X=Xt, y=yt, appeared=apt)
    print(f"train {X.shape} (mal {int(y.sum())}) | test {Xt.shape} (mal {int(yt.sum())}) -> {OUT}")


if __name__ == "__main__":
    main()
