# Response to the independent verification of 2026-09-21

Reviewed on 2026-10-21 against the tree as it stood that day (v3.3 shipped). Each finding
was first reproduced on the current code and artifacts by an independent agent run
(`dataset/results/review_response_reproductions.json`), then fixed. "Reproduced" below
means the defect existed in the current tree, not only in the September evidence.

| # | Finding | Reproduced | Fix | Verified by |
|---|---|---|---|---|
| 1 | `rf_adv`'s 0.820932 threshold was chosen on the EMBER *test* file; docs called 1 % FPR "by construction" / "held-out" | **Yes, bit-for-bit**: re-scoring all 200k test rows gives FPR 1,051/100,000 = 1.051 % (Wilson 0.990–1.116 %), TPR 76,728/100,000 = 76.73 %; 751/70,000 = 1.073 % outside the 30k calibration subsample; `operating_point.json` names `test.jsonl` | Documentation corrected everywhere the claim appeared (COMPARISON_REPORT §8, PITFALL_AUDIT P5, README). `package_model.py` now refuses a calibration file named like a test set unless `--allow-test-calibration`, and records that the result is an empirical calibration. The single-model image keeps 0.820932 and now states what it is. The submitted v3.3 ensemble never used this threshold: its fusion thresholds are set on fit folds and reported by grouped CV and a sealed holdout. | reproduction script re-run; doc audit |
| 2 | Server did not enforce its deadline: thread-pool timeout abandoned the caller, not the work (10 of 12 timed-out jobs stayed queued with their buffers); body read had no socket deadline (a 2-of-4-byte upload got no answer); a native call holding the GIL ran 6.0 s and returned "scored" | **Yes** on the old code (6.00 s, 10 queued, no answer after 6 s) | `defender/workers.py` + rewritten `defender/server.py`: inference runs in **forked worker processes** that are **SIGKILLed at the deadline and replaced**; admission is bounded by the worker count and a request waits at most until its own deadline (`saturated`); the body is read under a socket deadline and **streamed into the worker** (no buffer outlives its request); the budget covers read + wait + inference; the parent never runs the models (OpenMP-safe fork). Thread mode remains only as a logged, non-compliant fallback; both images set `DF_WORKER_MODE=process`, `DF_REQUEST_BUDGET_SECONDS=4.5`. | `tests/test_workers.py` (overrun kill + respawn, GIL-holding native sleep, crash recovery, saturation, no retained buffers), `tests/test_server_deadlines.py` (stalled upload answered in 1.0 s, overrun answered in budget, recovery), `tests/test_entrypoints.py` (both module entry points start); container probe: stalled upload → `{"result": 1}` at 4.51 s; gate 50/50, peak 942 MiB, no OOM |
| 3 | "Functionality-preserving" / "Lucas fix" claims rest on feature-space attribute edits and random augmentation; no binary produced, validated or executed | **Yes**: `adv_transforms.py` produces no bytes; `train_nfs_adversarial.py` samples at random with no model query | Relabelled throughout (COMPARISON_REPORT §8–§10 + closing caveat, PITFALL_AUDIT P10/Part 2/Part 7, THREAT_MODEL §6–§8, DATASHEET, README, both tool docstrings): synthetic feature-space perturbations; random (unguided) augmentation, which Lucas et al. show is weaker than attack-based training; "realizable" = intended, unverified. The v3+ byte-level suite (`eval_robustness.py`) is described as structurally rebuilt but not executed. | doc audit |
| 4 | HTTP evaluator credited answers that arrived after the 5 s limit (30 s timeout; late `1` counted as TP); transport failures aborted the run | **Yes** (mock server answering at 5.2 s counted as a detection) | `tools/evaluate.py`: `--deadline` (5.0 s); late, missing, malformed or transport-failed answers count against the detector (malware = miss, goodware = false positive), stay in the denominator, and are listed as operational errors; no abort. `grade_http.py`: 5 s deadline, a late answer is no answer. | mock-server reproduction re-run against the fixed tools |
| 5 | Metric code: per-row ROC path mis-scored ties (two tied cross-class scores → AUC 0 or 1); operating point took a ranked score then applied strict `>` (perfect two-sample case → 0 % TPR); PR area omitted an endpoint | **Yes** on the toy cases; on real score dumps every stored headline was within +1 sample of the correct value and AUC within 0.006 | `evaluate_models.metrics` uses scikit-learn's tie-aware ROC-AUC and average precision; `threshold_for_fpr` picks the lowest strict-`>` cut directly; `package_model` shares it; `--dump-scores` added. All four stored comparisons were recomputed on the same rows (`dataset/tools/recompute_metrics.sh`; old files kept as `*.pre-review.json`). | counterexamples; before/after table below |
| 6 | Recent split: random within family, unparseable row dropped, 140 trained goodware pooled with 60 held-out when reporting 0.5 %; 84/433 test malware feature-identical to a training row | **Yes, exactly** (0 SHA overlap; 84 duplicates; 6/60 held-out benign also have twins; benign rows carry no date) | Documents now report held-out goodware separately (1/60 = 1.7 %, Wilson 0.3–8.9 %) and the novel-feature subset (186/349 = 53.3 % for `rf_adv`). `split_recent.py` gained `--group-duplicates`, `--temporal`, `--keep-unparseable`. **Not re-split**: a new split invalidates `rf_adv`, which is trained on the current one; the v3+ fusion fit already excludes the 84 duplicates. | counts re-derived from the split files |
| 7 | README attributed the clean model's 66 % to `rf_adv` (58.66 %); config table showed `models/nfs`/0.25 vs the image's `rf_adv`/0.820932; "one env var away" while the image holds only `rf_adv` | **Yes** | README corrected (numbers, image-vs-code defaults table, switching instructions, test count). | doc audit |
| 8 | "Richer features exceed the runtime budget" and "proven ceiling" unsupported; 99.99 % arithmetic wrong (correct ≈ 67.6 %) | **Yes** (exact hypergeometric 67.64 %; the EMBER-2381 member is served within budget in v3.3) | COMPARISON_REPORT §4 arithmetic corrected with an erratum; §6/§8 budget-exclusion claim replaced by the measured fact. | doc audit |
| 9 | Tests covered the supplied model (`models/nfs`, 0.25), not the deployed configuration; no timeout/error-handling tests; `Model.__init__` did not check manifest digests | **Yes** | `Model` now verifies every manifest SHA-256 and size at load (`DF_SKIP_MANIFEST_VERIFY=1` to opt out, reported in `/model`); `tests/test_integrity.py`; deployed-configuration server test (`rf_adv`, 0.820932); deadline/worker/entry-point tests. Suite: **94 tests** (the commit message of 3b579be says 96; 94 is the measured count). | test run |
| lit. | ERDALT certificate implication; Lucas equivalence; AL/SSL F1 presented as a solution | **Yes** (ERDALT and Lucas wording; the F1 passage was labelled F1 but implied "our exact stack") | SOTA_RESEARCH.md and the Lucas passages reworded. | doc audit |

## What remains open

* **A calibration partition disjoint from the final EMBER test** for the single-model image,
  with the threshold frozen before evaluation. Not done: it requires retraining `rf_adv`
  (the only honest way to keep calibration rows out of training), and the single-model
  image is no longer the submission. The numbers above are reported as calibration-set
  and fixed-threshold-test figures instead.
* **A grouped, temporal re-split of the recent set** plus retraining of `rf_adv` on it.
  The tooling exists (`split_recent.py` options); the current reported figures use the
  novel-feature subset instead.
* **Executable-level adversarial robustness**: producing functionality-preserving binaries
  and running them. Nothing in this repository claims it any more.
* **Memory headroom**: the forked-worker server peaks at ~942 MiB of the 1 GiB limit after
  six 60+ MB benign files (thread pool: 897 MiB; frozen v3: 1024 MiB). The course set
  peaks at ~230 MiB.

## Recomputed comparison numbers (finding 5)

All four stored comparisons were re-evaluated on the same rows (same files, same
`--limit-per-class`, same seed) with the corrected metrics; previous values are kept as
`dataset/results/*.pre-review.json`, per-model scores are now dumped under
`dataset/results/scores/`, and the full table is in `reports/review-response-2026-10-21/recompute_metrics.log`.
**No stored conclusion changes.**

| Set (rows) | Metric | Change |
|---|---|---|
| EMBER temporal, 25k/25k | TPR @ 1 % FPR, all five models | unchanged (supplied 71.16 %, retrained 58.73 %, rf_tuned 77.87 %, rf_augmented 79.92 %) |
| EMBER temporal | ROC-AUC | ≤ 3e-5 |
| EMBER temporal | PR-AUC (now average precision) | −4.6e-4 … +1.4e-4 |
| recent_test, 60/433 | TPR @ 1 % FPR, rf_tuned and rf_augmented | **+1 sample each** (38.11 → 38.34 %, 28.18 → 28.41 %): the strict-threshold selection admits one more detection at the same FPR (0/60) |
| recent_test | PR-AUC | +0.0024 (endpoint now included) |
| recent_drift, 200/1455 | TPR @ 1 % FPR | supplied unchanged (15.12 %); rf_tuned +1 sample (34.23 → 34.30 %) |
| recent_drift | ROC-AUC | supplied −2.4e-4 (ties); rf_tuned +1e-5 |

The adversarial-training results (`adversarial_training.json`) were not produced by
`evaluate_models.metrics` (they are fixed-threshold counts with Wilson intervals) and were
reproduced exactly by the review; they are unchanged.

## Memory follow-up (2026-10-21)

Splitting the cgroup counter showed anonymous memory reaching ~950 MiB while a 67 MB benign
file is scored with two forked workers (idle ~400 MiB). An in-process profile attributes
~400 MiB of transient to the EMBER feature extraction itself on such a file, so two
concurrent large requests cannot fit under 1 GiB in any design; each idle worker adds
~100 MiB. Both images therefore run **one worker** (`DF_WORKERS=1`): a second concurrent
request waits for the worker up to its own deadline instead of doubling the transient
(course-set files take < 100 ms each), and idle memory drops by ~100 MiB. The gate log
`reports/review-response-2026-10-21/container_gate_v33_final_1worker_quiet.log` records
the result (arm64, one worker: course set 50/50 at p95 42 ms, idle 209 MiB, the six 60+ MB
benign files answered `0` in 2.0–3.3 s, cgroup peak 864 MiB, **anonymous memory at most
450 MiB** while scoring the 67 MB file, no OOM).

**amd64, under emulation on this arm64 host** (`container_gate_v33_final_1worker_amd64_quiet.log`):
course set 50/50 at p95 65 ms; the six large files answered `0` in 3.1–4.5 s (the 67 MB
file at the budget edge; an earlier two-worker emulated run answered it `1` on overrun);
cgroup peak 952 MiB and **anonymous memory up to 949 MiB** on that file. The emulator's own
translation memory is charged to the container, so this number is not the native x86
figure — which has **not** been measured and is the main remaining uncertainty for the
grading host. The course-set files are ≤ 2.9 MB and peak at ~320 MiB under emulation.
