# MLSEC PE Defender — retrained & adversarially hardened

A self-contained Windows PE malware classifier served over HTTP in a Docker
container, built for the MLSEC "defender's challenge" (goals: FPR ≤ 1 %, TPR ≥ 95 %,
≤ 1 GB RAM, ≤ 5 s/sample). It takes the supplied *Need-For-Speed* (NFS) random-forest
feature space, **retrains** it on a temporally-split, drift-aware dataset, and
**adversarially hardens** it against functionality-preserving evasion.

The runtime ships no scikit-learn and never unpickles anything: the forest is exported
to plain `.npy` arrays that are memory-mapped at startup.

## Results (honest)

Measured on held-out data; full method, confidence intervals, and limits in
[`dataset/docs/COMPARISON_REPORT.md`](dataset/docs/COMPARISON_REPORT.md).

| | Supplied | `rf_augmented` (clean) | **`rf_adv` (deployed)** |
|---|---|---|---|
| FPR @ shipped threshold | 13 % | 1 % | **1 %** |
| EMBER temporal TPR @ 1 % FPR | 71.2 % | 79.5 % | 76.7 % |
| Recent-malware detection (held-out) | ~9 % | 66 % | **59 %** |
| Combined evasion attack (held-out) | — | 7 % | **55 %** |
| Container: RAM / p95 latency | — | — | **147 MiB / 48 ms** |

`rf_adv` hardens the cheap realizable evasions (combined attack **7 % → 55 %**, packing
**21 % → 76 %**) at a 2.8-point clean-TPR cost. **Honest limits, measured and stated:**
it does *not* transfer to an untrained attack mechanism, and full feature-mimicry still
evades ~99 %. The ≥ 95 % TPR goal is structurally out of reach in the NFS feature space
(needs richer byte/string features). See the docs for the full story, including a
7-dimension adversarial self-audit that caught real defects in an earlier draft.

## Quick start

```bash
cd defender_product
docker build -t mlsec-defender .
docker run --rm -m 1g -p 8080:8080 mlsec-defender
```

```bash
curl -XPOST --data-binary @sample.exe \
     -H "Content-Type: application/octet-stream" http://127.0.0.1:8080/
# -> {"result": 1}   (1 = malicious)
```

## Layout

```
defender_product/     the deployable container
  defender/           sklearn-free runtime (features, hashing, forest, HTTP server)
  models/rf_adv/      the deployed adversarially-hardened model (.npy arrays)
  tools/              legacy-model export + evaluation
  tests/              sklearn-equivalence + server tests
  Dockerfile, README.md
dataset/
  tools/              dataset build, training, adversarial training, evaluation
    train_nfs_adversarial.py   adversarial training (Lucas recipe)
    adv_transforms.py          functionality-preserving attack transforms
    evaluate_adversarial.py    held-out robustness evaluation with CIs
    fast_score.py              batch scorer, bit-exact to the runtime
  docs/               COMPARISON_REPORT, THREAT_MODEL, DATASHEET, PITFALL_AUDIT
  results/            evaluation JSONs (with confidence intervals)
reports/              per-paper analysis writeups
```

## Reproduce

Training and evaluation need the datasets, which are **not** in this repo (see below).
With them in `dataset/work/`:

```bash
# adversarial training (reproduces the deployed model)
python dataset/tools/train_nfs_adversarial.py \
  --train work/ember_official/train.jsonl --extra-train work/recent_train.jsonl \
  --out models/nfs_rf_adv --max-per-class 150000 --adv-frac 0.6 --adv-mode all

# held-out robustness evaluation
python dataset/tools/evaluate_adversarial.py \
  --models models/nfs_rf_augmented models/nfs_rf_adv --thresholds 0.756536 0.820932 \
  --ember-test work/ember_official/test.jsonl \
  --recent-test work/recent_test.jsonl --recent-train work/recent_train.jsonl \
  --out results/adversarial_training.json
```

## What is deliberately NOT in this repo

This is defensive security research; the sensitive inputs are excluded on purpose:

- **No malware.** The MalwareBazaar samples used for training/evaluation are not
  redistributed. `dataset/tools/collect_malwarebazaar.py` documents how to fetch them
  (they arrive as AES-zip archives, password `infected`, and are handled inert).
- **No datasets.** The EMBER 2018 feature JSONLs (~tens of GB) and harvested goodware
  are not included; EMBER is public (elastic/ember).
- **No papers.** The 26 course papers are copyrighted and are not redistributed; the
  audit in `dataset/docs/PITFALL_AUDIT.md` references them by citation.
- **No secrets.** API keys are read from the environment (e.g. `VT_API_KEY`), never
  committed.

Only the deployed `rf_adv` model is included so the container builds out of the box.

## Ethics & scope

The malware-collection and adversarial-example tooling here is dual-use and provided
for **defensive** research and coursework: measuring and hardening a detector's
robustness. It handles malware only as password-protected archives and never executes
or writes decrypted samples to disk.
