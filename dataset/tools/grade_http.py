#!/usr/bin/env python3
"""Grade a running defender over HTTP exactly like the course harness: POST every sample of
a manifest-described set (csce704-reference-v1) as raw bytes to / and read {"result": 0|1}.
Sends bytes only; never executes anything. An unanswered/invalid reply counts as wrong.

usage: grade_http.py <set_dir> [label] [url]
"""
import json, pathlib, sys, time, urllib.request

GS = pathlib.Path(sys.argv[1])
label = sys.argv[2] if len(sys.argv) > 2 else "model"
url = sys.argv[3] if len(sys.argv) > 3 else "http://127.0.0.1:8080/"
tp = fn = fp = tn = errs = 0
lat, fps, fns = [], [], []
for s in json.load(open(GS / "manifest.json"))["samples"]:
    sub = "malware" if s["is_malware"] else "goodware"
    body = (GS / sub / f"{s['sha256']}.bin").read_bytes()
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={"Content-Type": "application/octet-stream"})
    t = time.time()
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            res = json.loads(r.read()).get("result")
    except Exception:
        res = None
    lat.append(time.time() - t)
    if res not in (0, 1):
        errs += 1
        res = 0 if s["is_malware"] else 1          # count non-answers against us
    if s["is_malware"]:
        tp += res == 1; fn += res == 0
        if res == 0:
            fns.append(s.get("family") or "unlabeled")
    else:
        fp += res == 1; tn += res == 0
        if res == 1:
            fps.append(s.get("source_name"))
tpr, fpr = tp / (tp + fn), fp / (fp + tn)
lat.sort()
ok = tpr > 0.95 and fpr < 0.01
print(f"[{label}] TP={tp} FN={fn} FP={fp} TN={tn} | TPR={tpr*100:.1f}% FPR={fpr*100:.1f}% | "
      f"{'PASS' if ok else 'FAIL'} | errors={errs} | latency p95={lat[int(.95*len(lat))]*1000:.0f}ms "
      f"max={lat[-1]*1000:.0f}ms")
if fps:
    print(f"   FPs: {fps}")
if fns:
    print(f"   misses: {fns}")
sys.exit(0 if ok else 1)
