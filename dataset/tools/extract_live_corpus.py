#!/usr/bin/env python3
"""Live-extract (lief-0.17) EMBER-2381 features for the whole benign + recent-malware
corpus and cache them. This is the confound-fix input: benign and malware both go
through the SAME live pipeline as serving. Tags benign native vs managed so we can
check for a type shortcut later.
"""
from __future__ import annotations
import json, pathlib, sys, time
import numpy as np

sys.path.insert(0, "dataset/tools")
import ember_compat  # noqa: F401
import ember, pyzipper

EXT = ember.PEFeatureExtractor(2, print_feature_warning=False)
CACHE = pathlib.Path("dataset/work/live_corpus"); CACHE.mkdir(parents=True, exist_ok=True)


def vec(b):
    return np.asarray(EXT.feature_vector(b), dtype=np.float32)


def extract_benign():
    rows = [json.loads(l) for l in open("dataset/goodware/index.jsonl")]
    X, types = [], []
    t0 = time.time()
    for i, r in enumerate(rows):
        p = pathlib.Path(f"dataset/goodware/pe/{r['sha256']}.bin")
        if not p.exists():
            continue
        member = (r.get("member") or "").lower()
        native = r.get("source") == "chocolatey" or "/native/" in member or member.endswith(".exe")
        try:
            X.append(vec(p.read_bytes())); types.append("native" if native else "managed")
        except Exception:
            continue
        if (i + 1) % 500 == 0:
            print(f"  benign {i+1}/{len(rows)} ({(time.time()-t0):.0f}s)", file=sys.stderr)
    return np.asarray(X, dtype=np.float32), np.array(types)


def extract_malware(split_jsonl):
    shas = [json.loads(l)["sha256"] for l in open(split_jsonl) if json.loads(l).get("label") == 1]
    X = []
    t0 = time.time()
    for i, s in enumerate(shas):
        z = pathlib.Path(f"dataset/quarantine/archives/{s}.zip")
        if not z.exists():
            continue
        try:
            with pyzipper.AESZipFile(z) as a:
                a.setpassword(b"infected"); b = a.read(a.infolist()[0])
            X.append(vec(b))
        except Exception:
            continue
        if (i + 1) % 200 == 0:
            print(f"  malware[{pathlib.Path(split_jsonl).stem}] {i+1}/{len(shas)} ({(time.time()-t0):.0f}s)", file=sys.stderr)
    return np.asarray(X, dtype=np.float32)


def main():
    print("extracting benign (live, lief-0.17)...", file=sys.stderr)
    Xb, tb = extract_benign()
    np.save(CACHE / "X_benign.npy", Xb); np.save(CACHE / "benign_types.npy", tb)
    print(f"  benign {Xb.shape}: {int((tb=='native').sum())} native / {int((tb=='managed').sum())} managed", file=sys.stderr)

    if (CACHE / "X_mal_train.npy").exists() and (CACHE / "X_mal_test.npy").exists():
        print("malware cache present -> skipping malware re-extraction", file=sys.stderr)
    else:
        print("extracting recent malware (live)...", file=sys.stderr)
        Xmtr = extract_malware("dataset/work/recent_train.jsonl")
        Xmte = extract_malware("dataset/work/recent_test.jsonl")
        np.save(CACHE / "X_mal_train.npy", Xmtr)
        np.save(CACHE / "X_mal_test.npy", Xmte)
        print(f"  malware train {Xmtr.shape}  test {Xmte.shape}", file=sys.stderr)
    print(f"cached to {CACHE}")


if __name__ == "__main__":
    main()
