# Response to the independent verification of 2026-09-21

*Last edited 2026-10-22. Refers to images `mlsec-defender:v33` (arm64, id 82413471f970…) and
`mlsec-defender:v33-amd64` (id df8cc840c35e…), built from `defender_product/Dockerfile.ensemble` with the
serving code committed as b901710 on `release/sure-shot-v3.1` (the image's `defender/*.py` match that
commit byte for byte), and to `mlsec-defender-submission-v33.zip` (sha256
8d3ae43c01031e5bb6536f10b41b803792475013e4e02cca1992d683e7de88b8),
produced by `dataset/tools/package_submission.sh v33`, which starts the image built from the zip
and requires it to serve before reporting success. The zip packaged on 2026-10-21 lacked
`defender/workers.py` and its image could not start; that zip was replaced on 2026-10-22.*

Reviewed on 2026-10-21 against the tree as it stood that day (v3.3 shipped). Each finding
was first reproduced on the current code and artifacts by an independent agent run
(`dataset/results/review_response_reproductions.json`), then fixed. "Reproduced" below
means the defect existed in the current tree, not only in the September evidence.

| # | Finding | Reproduced | Fix | Verified by |
|---|---|---|---|---|
| 1 | `rf_adv`'s 0.820932 threshold was chosen on the EMBER *test* file; docs called 1 % FPR "by construction" / "held-out" | **Yes, bit-for-bit**: re-scoring all 200k test rows gives FPR 1,051/100,000 = 1.051 % (Wilson 0.990–1.116 %), TPR 76,728/100,000 = 76.73 %; 751/70,000 = 1.073 % outside the 30k calibration subsample; `operating_point.json` names `test.jsonl` | Documentation corrected everywhere the claim appeared (COMPARISON_REPORT §8, PITFALL_AUDIT P5, README). `package_model.py` now refuses a calibration file named like a test set unless `--allow-test-calibration` (a filename heuristic, no more), and new runs write a `note` into `operating_point.json`; the shipped `models/rf_adv/operating_point.json` was annotated by hand on 2026-10-22 (threshold unchanged; the file is not covered by the manifest). The single-model image keeps 0.820932 and now states what it is. The submitted v3.3 ensemble never used this threshold: its fusion thresholds are set on fit folds and reported by grouped CV and a sealed holdout. | reproduction script re-run; doc audit |
| 2 | Server did not enforce its deadline: thread-pool timeout abandoned the caller, not the work (10 of 12 timed-out jobs stayed queued with their buffers); body read had no socket deadline (a 2-of-4-byte upload got no answer); a native call holding the GIL ran 6.0 s and returned "scored" | **Yes** on the old code (6.00 s, 10 queued, no answer after 6 s) | `defender/workers.py` + rewritten `defender/server.py`: inference runs in **forked worker processes** that are **SIGKILLed at the deadline and replaced**; admission is bounded by the worker count and a request waits at most until its own deadline (`saturated`); the body is read under a socket deadline and **streamed into the worker** (no buffer outlives its request); the budget covers read + wait + inference; the parent never runs the models (OpenMP-safe fork). Thread mode remains only as a logged, non-compliant fallback; both images set `DF_WORKER_MODE=process`, `DF_REQUEST_BUDGET_SECONDS=4.5`. Idle keep-alive connections wait 60 s for the next request (the timeout is restored before every request line; the final verification found it was left at the remaining budget after a body read). | `tests/test_workers.py` (overrun kill + respawn, GIL-holding native sleep, crash recovery, saturation, no retained buffers), `tests/test_server_deadlines.py` (stalled upload answered in 1.0 s, overrun answered in budget, recovery), `tests/test_entrypoints.py` (both module entry points start); container probe: stalled upload → `{"result": 1}` at the budget (`reports/review-response-2026-10-21/stalled_upload_probe.log`); gates in the same folder (`container_gate_v33_final_*`). Two regressions in this fix were found and corrected the next day: see the re-verification section. |
| 3 | "Functionality-preserving" / "Lucas fix" claims rest on feature-space attribute edits and random augmentation; no binary produced, validated or executed | **Yes**: `adv_transforms.py` produces no bytes; `train_nfs_adversarial.py` samples at random with no model query | Relabelled throughout (COMPARISON_REPORT §8–§10 + closing caveat, PITFALL_AUDIT P10/Part 2/Part 7, THREAT_MODEL §6–§8, DATASHEET, README, both tool docstrings): synthetic feature-space perturbations; random (unguided) augmentation, which Lucas et al. show is weaker than attack-based training; "realizable" = intended, unverified. The v3+ byte-level suite (`eval_robustness.py`) is described as structurally rebuilt but not executed. | doc audit |
| 4 | HTTP evaluator credited answers that arrived after the 5 s limit (30 s timeout; late `1` counted as TP); transport failures aborted the run | **Yes** (mock server answering at 5.2 s counted as a detection) | `tools/evaluate.py`: `--deadline` (5.0 s); late, missing, malformed or transport-failed answers count against the detector (malware = miss, goodware = false positive), stay in the denominator, and are listed as operational errors; no abort. `grade_http.py`: 5 s deadline, a late answer is no answer. Both tools accept only HTTP 200 with an integer 0/1 (booleans are not answers) and never abort on an unreadable file or a dropped connection. | `tests/test_evaluators.py`: mock server answering late, dropping, malformed JSON, a boolean, HTTP 500 — every sample stays in the denominator and counts against the detector |
| 5 | Metric code: per-row ROC path mis-scored ties (two tied cross-class scores → AUC 0 or 1); operating point took a ranked score then applied strict `>` (perfect two-sample case → 0 % TPR); PR area omitted an endpoint | **Yes** on the toy cases; on real score dumps every stored headline was within +1 sample of the correct value and AUC within 0.0062 | `evaluate_models.metrics` uses scikit-learn's tie-aware ROC-AUC and, under the unchanged key `pr_auc`, average precision (a different estimator from the former trapezoid); `threshold_for_fpr` picks the lowest strict-`>` cut directly; `package_model` shares it; `--dump-scores` added. All four stored comparisons were recomputed on the same rows (`dataset/tools/recompute_metrics.sh`; old files kept as `*.pre-review.json`). | `tests/test_metrics.py` (the review's counterexamples plus 100 random tied-score cases against scikit-learn and a brute-force threshold search); before/after table below |
| 6 | Recent split: random within family, unparseable row dropped, 140 trained goodware pooled with 60 held-out when reporting 0.5 %; 84/433 test malware feature-identical to a training row | **Yes, exactly** (0 SHA overlap; 84 duplicates; 6/60 held-out benign also have twins; benign rows carry no date) | Documents now report held-out goodware separately (1/60 = 1.7 %, Wilson 0.3–8.9 %) and the novel-feature subset (186/349 = 53.3 % for `rf_adv`). `split_recent.py` gained `--group-duplicates`, `--temporal`, `--keep-unparseable`. **Not re-split**: a new split invalidates `rf_adv`, which is trained on the current one; the v3+ fusion fit already excludes the 84 duplicates. | counts re-derived from the split files |
| 7 | README attributed the clean model's 66 % to `rf_adv` (58.66 %); config table showed `models/nfs`/0.25 vs the image's `rf_adv`/0.820932; "one env var away" while the image holds only `rf_adv` | **Yes** | README corrected (numbers, image-vs-code defaults table incl. `DF_WORKERS=1`, switching instructions, test count, single-flight semantics). | doc audit |
| 8 | "Richer features exceed the runtime budget" and "proven ceiling" unsupported; 99.99 % arithmetic wrong (correct ≈ 67.6 %) | **Yes** (exact hypergeometric 67.64 %; the EMBER-2381 member is served within budget in v3.3) | COMPARISON_REPORT §4 arithmetic corrected with an erratum; §6/§8 budget-exclusion claim replaced by the measured fact; the "not reachable / structurally caps / is the ceiling" wording (README, COMPARISON §1 and §6, SOTA_RESEARCH) reworded to the observation that the NFS models tried stopped at ~80 % (one RF family, one aborted LightGBM run). | doc audit |
| 9 | Tests covered the supplied model (`models/nfs`, 0.25), not the deployed configuration; no timeout/error-handling tests; `Model.__init__` did not check manifest digests | **Yes** | `Model` now verifies every manifest SHA-256 and size at load and refuses a directory without a manifest (`DF_SKIP_MANIFEST_VERIFY=1` opts out, reported in `/model`); the manifest is unsigned and does not cover `operating_point.json`; `tests/test_integrity.py`; deployed-configuration server test (`rf_adv`, 0.820932); deadline/worker/entry-point tests. Suite: **106 tests** on branch `release/sure-shot-v3.1` (`cd defender_product && .venv/bin/python -m unittest <the 15 tracked test modules>`; the working tree on the development machine also holds another session's untracked `tests/test_ember2024.py`, 5 tests, so `discover` reports 111 there; earlier versions of this row said 92, 94 and 108, and the message of commit 3b579be said 96). | test run |
| lit. | ERDALT certificate implication; Lucas equivalence; AL/SSL F1 presented as a solution | **Yes** (ERDALT and Lucas wording; the F1 passage was labelled F1 but implied "our exact stack") | SOTA_RESEARCH.md and the Lucas passages reworded. | doc audit |

## What remains open

* The `package_model.py` test-set guard is a filename heuristic; nothing compares calibration rows against the final evaluation rows.
* Native x86 memory and latency are unmeasured (only emulated amd64 on this arm64 host).
* The manifest is unsigned: whoever can rewrite the arrays can rewrite the manifest.

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
* **Memory headroom**: see the memory follow-up below (the first forked-worker build
  peaked at the 1 GiB limit; the thread-pool v3.3 build at 897 MiB and the frozen v3 at
  1024 MiB, both in `reports/v33-2026-10-20/container_gate_v33_quiet.log` and
  `container_gate_v3_baseline_quiet.log`). The course set peaks at 382 MiB cgroup (page
  cache included) on arm64 and 318 MiB under amd64 emulation in the final gates
  (`reports/review-response-2026-10-21/container_gate_v33_final_quiet_memsplit.log`,
  `container_gate_v33_final_amd64_quiet.log`).

## Recomputed comparison numbers (finding 5)

All four stored comparisons were re-evaluated on the same rows (same files, same
`--limit-per-class`, same seed) with the corrected metrics; previous values are kept as
`dataset/results/*.pre-review.json`, per-model scores are now dumped under
`dataset/results/scores/`, and the full table is in `reports/review-response-2026-10-21/recompute_metrics.log`.
**No stored conclusion changes.**

| Set (rows) | Metric | Change |
|---|---|---|
| EMBER temporal, 25k/25k | TPR @ 1 % FPR | unchanged for the three models with a stored entry (supplied 71.16 %, retrained 58.73 %, rf_tuned 77.87 %); **+1 sample** for rf_augmented (79.920 → 79.924 %, `ember_aug.json`) and rf_adv (newly evaluated) |
| EMBER temporal | ROC-AUC | ≤ 3e-5 |
| EMBER temporal | PR-AUC (now average precision) | −4.6e-4 … +1.4e-4 |
| recent_test, 60/433 | TPR @ 1 % FPR, rf_tuned and rf_augmented | **+1 sample each** (38.11 → 38.34 %, 28.18 → 28.41 %): the strict-threshold selection admits one more detection at the same FPR (0/60) |
| recent_test | PR-AUC | +0.0024 (rf_tuned) / +0.0023 (rf_augmented) (endpoint now included) |
| recent_drift, 200/1455 | TPR @ 1 % FPR | supplied unchanged (15.12 %); rf_tuned +1 sample (34.23 → 34.30 %) |
| recent_drift | ROC-AUC | supplied −2.4e-4 (ties); rf_tuned +1e-5 |

The adversarial-training results (`adversarial_training.json`) were not produced by
`evaluate_models.metrics` (they are fixed-threshold counts with Wilson intervals) and were
reproduced exactly by the review; they are unchanged.

## Memory follow-up (2026-10-21)

Splitting the cgroup counter showed anonymous memory reaching 952 MiB while a 67 MB benign
file was scored with two forked workers, with 313 MiB anonymous idle (the author's
two-worker gate log of 2026-10-21, since overwritten, as quoted in
`dataset/results/review_response_verification.json`; the verifiers' own 20 ms sampling of
that build measured 896–901 MiB on a fresh container, 1001 MiB after 20–30 prior large
files, idle 178 MiB; the two-worker cgroup gate `container_gate_v33_final_quiet.log` shows
398 MiB after the course set and a 1024 MiB peak). The transient belongs to the per-request feature
extraction (the byte histogram alone, see below), so two concurrent large requests cannot
fit under 1 GiB in any design; each idle worker adds ~130 MiB anonymous (313 → 182 MiB) or
~190 MiB cgroup (398 → 209 MiB, `container_gate_v33_final_1worker_quiet.log`). Both images
therefore run **one worker** (`DF_WORKERS=1`): a second concurrent request waits for the
worker up to its own deadline instead of doubling the transient (course-set files take at
most 58 ms each on native arm64 in the final gate, up to 302 ms under amd64 emulation).

After the byte-histogram fix and worker recycling (re-verification section), the final
arm64 image gives, on a quiet host with a 20 ms in-container sampler
(`container_gate_v33_final_quiet_memsplit.log`, image 82413471f970): course set 50/50 at
p95 40 ms, max 58 ms; the six 60+ MB benign files answered `0` in 2.06–2.75 s; **cgroup
peak 603 MiB** after them, of which 165 MiB is page cache (`file=165MiB` in the same log;
an independent re-run of the previous build measured a 435 MiB peak with no page cache
and the same anonymous figures, `dataset/results/review_response_final_check.json`);
**anonymous memory at most 409 MiB** while scoring the 67 MB file
three times, idle 182 MiB; no OOM; container log clean. Against the same container
(`stalled_upload_probe.log`): a benign PE sent 50 ms after a stalled upload started is
scored `0` in 16 ms while the stall is still pending; the stalled upload is answered `1`
at 4.52 s; a benign PE after a 40 s idle gap is scored `0`; a drip upload (one byte per
0.5 s) is answered `1` at 4.51 s; two requests on one keep-alive connection 6 s apart are
both scored `0`.

**amd64, under emulation on this arm64 host** (`container_gate_v33_final_amd64_quiet.log`,
image df8cc840c35e): course set 50/50 at p95 78 ms, max 302 ms; five of the six large
files answered `0` in 3.3–4.0 s and **the 66.8 MB file overran the 4.5 s budget (4.52 s)
and was answered `1`** in this run, where the previous run of the same configuration took
3.95 s (that superseded log is the version of `container_gate_v33_final_amd64_quiet.log` at
commit 39c62b5); cgroup peak 516 MiB, anonymous memory at most 467 MiB, idle 238 MiB. Emulation
ran 1.25–1.95× slower than the native arm64 build on these files (p95 78 vs 40 ms; 67 MB
file 4.52 vs 2.75 s; per-file ratios 1.25–1.77) and charges the emulator's own memory to the container, so these are
conservative; the native x86 figures have **not** been measured. On the grading host a
file of that size would sit at the edge of the budget; the course-set files are ≤ 2.9 MB
and peak at 318 MiB under emulation.

## Re-verification of the fixes (2026-10-22) and what it found

Five independent agents re-derived each fix (`dataset/results/review_response_verification.json`);
a final three-agent pass and a provenance-only check followed (`dataset/results/review_response_final_check.json`).
The deadline fix, the evaluators, the metrics and the manifest check held up; the re-verification
also found defects introduced by the first fix, all corrected the same day:

| Found | Fix | Test |
|---|---|---|
| **Idle workers exited after 30 s.** The child's reply path left a 30 s timeout on its socket; the next idle `recv` timed out, the child exited, and the next request was answered `1` without scoring (`worker_failed`). Reproduced in-process and in the shipped container (a request after a 35 s pause → `1`). | `_recv_exact` resets the timeout when it is asked to block; recycling made explicit (below). | `test_workers.RegressionsFromVerification.test_idle_worker_does_not_exit_after_the_reply_timeout` (reply timeout shrunk to 0.3 s) |
| **Slow-drip uploads escaped the budget.** `rfile.read(n)` retried the per-recv timeout for every byte, so one byte every 3 s stretched a request to 9–16 s. | Body reads use `read1` (one `recv` per call) and the relay re-checks the deadline per chunk. | `test_server_deadlines.DripUploadTest` (one byte per 0.25 s, answered at the 1 s budget) |
| **The submission zip lacked `defender/workers.py`**; the image built from it could not start (the packaging check only listed modules). | Module added; `package_submission.sh` now starts the from-zip image and requires `/health` and a benign classification before it reports success. | packaging run |
| **Worker memory grew across large files** and the gate's 0.2 s sampler had understated the transient (verifier's 20 ms sampler: ~900 MiB anon on the 67 MB file, rising after repeated large files). Profiling attributed 509 MiB of it to EMBER's byte histogram (`np.bincount` casts the whole buffer to 64-bit; derived figure 66,763,664 B × 8, the profiling run itself was not logged). The EMBER strings extractor still lowercases a copy of the body (`ember_compat.py`, ~67 MB transient on the largest file). | Chunked histogram (identical counts, 32 MiB transient); workers recycle after 50 requests or any body ≥ 8 MiB without losing a request; no lowercase copy of the body in the command-line tell; gate samples anonymous memory every 20 ms in the container over three large requests. | `test_ember_compat_memory` (identical to the original on synthetic and real inputs; transient bound), `test_workers` recycling tests, gate log |
| Failed respawn never retried; a non-OS exception could drop a worker from the pool. | Respawn retries with backoff (5 attempts, then every 2 s indefinitely: the final verification pass, `dataset/results/review_response_final_check.json`, found the pool could stay empty for good after five failures); any exception retires and replaces the worker; a request whose deadline has already passed when it gets a worker is answered `1` without killing that worker. | `test_workers.FinalVerificationRegressions` |
| Response-document provenance: the stalled-upload probe (4.51 s), the thread-pool and frozen-v3 peaks were quoted without a log in the cited folder; "no EMBER headline changed" was off by one sample for two models; the suite count was 92/96, not 94. | Citations fixed; the stalled-upload probe is now saved as `reports/review-response-2026-10-21/stalled_upload_probe.log`. Third round (final verification): the test count was corrected again to the branch count (106); `PAPER_CONCEPTS.md` and `RICHER_FEATURES_ENSEMBLE.md` still carried the "Lucas recipe" / "ceiling" wording and were relabelled; the memory figures below were replaced by logged values; the gate script now lives at `dataset/tools/container_gate.sh`. | — |
