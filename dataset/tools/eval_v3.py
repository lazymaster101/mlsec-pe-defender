#!/usr/bin/env python3
"""End-to-end evaluation of the v3 serving code (defender.ensemble.Ensemble.analyze)
on raw bytes, exactly as the HTTP server would call it. Reads bytes only.

  --corpora course,goodware,local,malware   (grading only when --final is given)
Writes per-sample verdicts to dataset/work/exp/v3_<corpus>.jsonl and prints a summary.
Note: members are in-sample on their own training rows (ember_ft saw all live rows;
rf_adv saw recent_train), so the HONEST generalization numbers are the grouped-CV
ones printed by train_v3.py / exp_three.py. This run checks the serving code path,
the trust/tamper layers, fallbacks and latency.
"""
from __future__ import annotations
import argparse, collections, json, multiprocessing as mp, os, pathlib, sys, time

ROOT = pathlib.Path(__file__).resolve().parents[2]
PROD = ROOT / "defender_product"
_E = {}


VARIANTS = {  # same serving code, different artifacts
    "v3": {"DF_EMBER_FT": "models/ember_ft/ember_ft.txt", "DF_RF_DIR": "models/rf_adv", "DF_FUSION": "models/fusion.json"},
    "v4": {"DF_EMBER_FT": "models/ember_ft_v4/ember_ft.txt", "DF_RF_DIR": "models/rf_v4", "DF_FUSION": "models/fusion_v4.json"},
    "v41": {"DF_EMBER_FT": "models/ember_ft_v41/ember_ft.txt", "DF_RF_DIR": "models/rf_v41", "DF_FUSION": "models/fusion_v41.json"},
    "v31": {"DF_EMBER_FT": "models/ember_ft_v31/ember_ft.txt", "DF_RF_DIR": "models/rf_adv", "DF_FUSION": "models/fusion_v31.json"},
    "v32": {"DF_EMBER_FT": "models/ember_ft_v32/ember_ft.txt", "DF_RF_DIR": "models/rf_adv", "DF_FUSION": "models/fusion_v32.json"},
}


def _init(variant="v3"):
    sys.path.insert(0, str(PROD))
    os.environ.update(DF_EMBER_MODEL=str(PROD / "models/ember_gbdt/ember_gbdt.txt"), OMP_NUM_THREADS="1",
                      **{k: str(PROD / v) for k, v in VARIANTS[variant].items()})
    from defender.ensemble import Ensemble
    _E["m"] = Ensemble()


def _bytes(item):
    if item["kind"] == "zip":
        import pyzipper
        with pyzipper.AESZipFile(item["ref"]) as a:
            a.setpassword(b"infected"); return a.read(a.infolist()[0])
    return pathlib.Path(item["ref"]).read_bytes()


def work(item):
    b = _bytes(item); t = time.time()
    out = _E["m"].analyze(b)
    out.update(sha256=item["sha256"], label=item["label"], group=item["group"], is_exe=item.get("is_exe"),
               secs=round(time.time() - t, 4))
    return out


def items(corpus):
    sys.path.insert(0, str(ROOT / "dataset/tools"))
    import build_live_cache as B
    its = B.items_for(corpus)
    meta = {json.loads(l)["sha256"]: json.loads(l) for l in open(ROOT / f"dataset/work/live_cache/meta_{corpus}.jsonl")}
    for it in its:
        it["is_exe"] = not meta.get(it["sha256"], {}).get("pe", {}).get("is_dll", False)
    return its


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpora", default="course,goodware,local,malware")
    ap.add_argument("--final", action="store_true", help="also score the course grading set (do once, after freezing)")
    ap.add_argument("--variant", default="v3", choices=sorted(VARIANTS))
    ap.add_argument("--only-groups", type=pathlib.Path, help="json list: restrict goodware rows to these groups (e.g. the sealed v4 holdout)")
    args = ap.parse_args()
    corpora = args.corpora.split(",") + (["grading"] if args.final else [])
    out_dir = ROOT / "dataset/work/exp"; out_dir.mkdir(parents=True, exist_ok=True)
    rt = {json.loads(l)["sha256"] for l in open(ROOT / "dataset/work/recent_test.jsonl") if json.loads(l)["label"] == 1}
    only = set(json.load(open(args.only_groups))) if args.only_groups else None
    for corpus in corpora:
        its = items(corpus)
        if only is not None:
            its = [it for it in its if it["label"] == 1 or it["group"] in only]
        with mp.Pool(8, initializer=_init, initargs=(args.variant,)) as pool:
            res = pool.map(work, its, chunksize=8)
        tag = f"{args.variant}_{corpus}" + ("_holdout" if only is not None else "")
        with open(out_dir / f"{tag}.jsonl", "w") as fh:
            for r in res:
                fh.write(json.dumps(r) + "\n")
        reasons = collections.Counter(r["reason"] for r in res)
        lat = sorted(r["secs"] for r in res)
        pos = [r for r in res if r["verdict"] == 1]
        line = f"[{args.variant}:{corpus}] n={len(res)} flagged={len(pos)} ({len(pos)/len(res):.2%})"
        if corpus in ("goodware", "local", "course", "goodware2") or (corpus == "grading"):
            g = [r for r in res if r["label"] == 0]; ge = [r for r in g if r["is_exe"]]
            if g:
                line += f" | goodware FPR {sum(r['verdict'] for r in g)/len(g):.3%} EXE {sum(r['verdict'] for r in ge)}/{len(ge)}"
        if corpus in ("malware", "grading"):
            m = [r for r in res if r["label"] == 1]
            line += f" | malware TPR {sum(r['verdict'] for r in m)/len(m):.2%}"
            if corpus == "malware":
                mt = [r for r in m if r["sha256"] in rt]
                line += f" (recent_test {sum(r['verdict'] for r in mt)/len(mt):.2%})"
        print(line)
        print(f"     reasons {dict(reasons)} | latency p50 {lat[len(lat)//2]*1000:.0f}ms p99 {lat[int(.99*len(lat))]*1000:.0f}ms max {lat[-1]*1000:.0f}ms")
        if corpus in ("course", "grading"):
            for r in res:
                if (r["label"] == 0 and r["verdict"]) or (r["label"] == 1 and not r["verdict"]) or corpus == "course":
                    print(f"       {'FP' if r['label']==0 and r['verdict'] else ('FN' if r['label']==1 and not r['verdict'] else 'ok')} "
                          f"{r['group'][:30]:30s} {r['reason']:28s} score={r.get('score')} thr={r.get('threshold')} e={r.get('e')} r={r.get('r')} f={r.get('f')}")


if __name__ == "__main__":
    main()
