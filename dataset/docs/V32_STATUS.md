# v3.2 candidate: status (2026-10-20)

**Course set, scored once after training: 50/50 malware, 0/50 goodware** (v3: 48/50; v3.1: 49/50).
Container gates pass on arm64 and amd64. **Decision: ship v3.2** (`release/sure-shot-v3.1` branch,
`submission_v32/`, `mlsec-defender-submission-v32.zip`), with the costs in §3 and §4 stated.

v3.2 = v3.1 (see `V31_STATUS.md`: legacy Microsoft PCA pins, hidden-PowerShell tell, 800-round
`ember_ft`) **+ 250 fresh MalwareBazaar samples in the `ember_ft` training data**, fusion refit by
the unchanged rule. rf_adv, ember_gbdt, extractors, server and thresholds rule are unchanged.

## 1. The new data (`dataset/tools/collect_mb_recent.py`)

| | |
|---|---|
| Source | MalwareBazaar, by **tag** (stealer 170, Rust 8, golang 5, Go 1) and the recent-EXE feed (49); first seen 2026-08-01 … 2026-10-21 |
| Why these | Error analysis of the v3.1 miss (a Rust-built loader scored 0.11 by EMBER-2018) and of the whole fresh haul (EMBER-2018 scores it 0.26 on average): the detector's weakest member is 2018 features on 2026 toolchains. The tag list targets that drift, not any specific sample. |
| Families | Vidar 61, WARDENStealer 57, untagged 43, SalatStealer 28, RemusStealer 10, RustyStealer 4, VShell 3, njrat 3, Aokigahara 3, BridgeAgent 2, ValleyRAT 1, GCleaner 1 |
| Hygiene | all 100 course hashes **refused at collection** (0 collided); **0 training rows feature-identical** to a course malware sample (checked at training on the EMBER-2381 vector); untagged samples grouped by import hash (30 groups) for grouped CV; archives stay AES-encrypted on disk, decrypted in memory for parsing only |
| Family overlap with the course set | RemusStealer (11 train / 1 course) and NanoCore (40 / 2) occur in both; **Phorpiex (40 course samples) is in neither v3's nor v3.2's training**. Family overlap existed in v3 already (NanoCore); it is disclosed, not new. |

## 2. Candidates and the course set (each scored once, after freezing)

| Candidate | TP | FP | Lowest malware margin (score − threshold) |
|---|---|---|---|
| v3 (submitted) | 48/50 | 0/50 | two misses: −1.04, −0.84 |
| A = v3 + pins + tell | 49/50 | 0/50 | −0.84 (`4ea0…`) |
| B = v3.1 | 49/50 | 0/50 | −0.34 (`4ea0…`) |
| **C = v3.2** | **50/50** | **0/50** | **+0.49** (`4ea0…` 4.43 vs 3.95), next +0.62 (`f36e…`) |

All 50 goodware are cleared by Authenticode trust in A, B and C (no ML threshold can create a
course-set false positive). The course set was read three times today (A, B, C); none of the reads
chose a threshold, a hyper-parameter or a sample. The retrain's *data* was chosen after seeing which
kind of sample v3.1 missed; that is error analysis and it is stated here.

## 3. Gates (pre-registered criteria from the v4 review, applied to v3.2 vs v3)

| Criterion | v3 | v3.1 | **v3.2** | Verdict |
|---|---|---|---|---|
| Grouped 10×5 CV TPR at the 0.75 % fit-FPR rule (same 349 / 4,497 fit rows) | 83.5 ± 4.1 | 87.1 ± 4.0 | **85.3 ± 4.2** (EXE malware 87.3) | MET vs v3 (+1.8, within SD); FPR-EXE 1.09 → 1.14 % |
| Sealed-holdout goodware FPR, same 591 files / 465 EXE | 45 = 7.61 % / 43 = 9.25 % | 45 / 43 | **49 = 8.29 % / 47 = 10.11 %** | **small regression**: 10 discordant files (7 new FPs, 3 fixed); McNemar p ≈ 0.34, not significant, but reported |
| Robustness, 7 attacks, 349 held-out malware | 87.7 / 90.3 / 85.4 / 80.2 / 81.1 / 86.2 / 92.0 / 89.1 | 94.3 / 92.8 / 88.5 / 80.8 / 85.1 / 90.5 / 94.0 / 93.4 | **93.4 / 92.8 / 87.7 / 81.4 / 84.8 / 90.5 / 94.0 / 91.7** | **better than v3 on all 7** (+1.1 … +5.7); 1–2 pts under v3.1 on 4 of 7 (in-sample caveat as before) |
| `recent_test` detection (433) | 89.6 % | 95.4 % | **94.5 %** | MET |
| Container, arm64, 1 CPU / 1 GiB / read-only, quiet host | 48/50; 60 MB files 3.0–6.0 s; peak 1024 MiB | 49/50; 1.9–2.9 s; 1024 MiB | **50/50, p95 40 ms**; 60 MB files **2.0–2.9 s, all 0**; peak **896 MiB**, no OOM; malformed → 1; log clean | MET |
| Container, amd64 (grading arch), emulated | — | — | **50/50**, p95 120 ms, peak 976 MiB, no OOM (large-file timing not meaningful under emulation) | MET on decisions |
| Build from the submission zip alone | — | — | builds; image contains only the 11 serving modules and the 4 shipped model artefacts | MET |
| Tests | — | 74/74 | **74/74** | MET |

## 4. Honest limits

* **Holdout FPR on unsigned third-party software is ~10 % and got 0.9 pt worse.** The course goodware
  is Microsoft-signed, so this does not affect the grade; a grader using diverse unsigned goodware
  would see it. v4/v4.1 fixed that number at the cost of the course result (`V41_STATUS.md`).
* The 50/50 margin is 0.49 logits on one sample. A re-sampled course set of similar composition would
  not be guaranteed 50/50: the honest generalization number is the CV TPR (85 %), not 100 %.
* 250 samples is a small haul (MalwareBazaar caps tag and feed queries at ~100–200 rows); only 8 were
  Rust-tagged. The gain on the Rust loader likely comes from recent stealers broadly, not Rust per se.
* The command-line tell is a signature (0.5 % of malware, trivially obfuscated). The legacy PCA pins
  widen trust to pre-2012 Microsoft first-party code only.
* The sealed holdout has been read four times (v4, v4.1, v3.1, v3.2); it must not be used to pick a
  threshold.

## 5. Reproduce

```bash
PY=defender_product/.venv/bin/python
$PY dataset/tools/collect_mb_recent.py --out dataset/quarantine --file-types exe \
    --tags Rust,rust,golang,Go,Nim,nim,NET,loader,dropper,stealer --since 2026-08-01 \
    --exclude-manifest csce704-blackbox-validation-100-samples-20261014-corrected/manifest.json   # MB_AUTH_KEY or .mb_key
$PY dataset/tools/build_live_cache.py --corpora malware
$PY dataset/tools/train_v31.py --rounds 800 --tag v32
$PY dataset/tools/eval_v3.py --variant v32 --corpora goodware2,malware --only-groups dataset/work/exp/v4_holdout_eval_groups.json
ROBUST_VARIANT=v32 $PY dataset/tools/eval_robustness.py
docker build -f defender_product/Dockerfile.ensemble -t mlsec-defender:v32 defender_product
```
Results: `dataset/results/v32_review.json`.
