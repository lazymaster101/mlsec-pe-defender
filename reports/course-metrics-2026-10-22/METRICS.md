# Course validation set metrics — v3.3 image built from the submission zip (2026-10-22)

**Disclosure.** This is one more read of the course validation set
(`csce704-blackbox-validation-100-samples-20261014-corrected`, 50 malware / 50 goodware). It was
taken for reporting only: the model artifacts are frozen, no threshold, hyper-parameter or training
sample was chosen from it. Counting the in-process scoring of 2026-10-20, the two quiet container
gates of 2026-10-20 and the seven container re-gates of 2026-10-21 (serving-code fixes, model
untouched), this is the eleventh recorded read by v3.3; every one of the eleven gave TP=50 FN=0
FP=0 TN=50.

**How it was scored.** Image `mlsec-defender:v33-fromzip`
(`sha256:4548edda77d36e4f66c6c5de16d365e32156cc0144759fd2f899950f84cc4de8`, built from
`mlsec-defender-submission-v33.zip`, sha256 `8d3ae43c…e88b8`), started with
`docker run -d --name course_metrics_v33 -m 1g --cpus 1 --read-only -p 127.0.0.1:19810:8080`,
no tmpfs. Each sample was POSTed as `application/octet-stream` to `/` with the harness rule: a
non-200, non-JSON, non-integer or >5 s answer counts as wrong (`no_answers=0`, `late=0`).
Scorer: `score_course_http.py` (stdlib only, bytes read and POSTed, nothing executed).
Per-sample rows: `v33_fromzip_strict_per_sample.jsonl`; summary: `v33_fromzip_strict_summary.json`;
container log: `v33_fromzip_strict_container.log` (1 ready + 100 classified lines, no errors);
`/model` snapshot: `v33_fromzip_model_endpoint.json` (model_name ensemble-v33, threshold 4.081908667053039).

## Confusion matrix (malware = positive)

|                | predicted malware (1) | predicted goodware (0) |
|----------------|-----------------------|------------------------|
| actual malware (50)  | TP = 50 | FN = 0 |
| actual goodware (50) | FP = 0  | TN = 50 |

## Per-class metrics (one-vs-rest, each class taken as the positive class in turn)

| class as positive | support | TPR / recall | FPR | precision | F1 |
|-------------------|---------|--------------|-----|-----------|----|
| malware  | 50 | 50/50 = 1.000 | 0/50 = 0.000 (goodware called malware) | 50/50 = 1.000 | 1.000 |
| goodware | 50 | 50/50 = 1.000 | 0/50 = 0.000 (malware called goodware) | 50/50 = 1.000 | 1.000 |

The goodware-class FPR is algebraically the malware-class FNR (0/50), and vice versa.

## Overall (n = 100)

| metric | value |
|--------|-------|
| accuracy | 100/100 = 1.000 |
| error rate | 0.000 |
| micro-F1 (= accuracy for single-label binary) | 1.000 |
| macro-F1 | 1.000 |
| weighted-F1 | 1.000 |
| balanced accuracy | 1.000 |
| Matthews correlation coefficient | 1.000 |
| course PASS bar (TPR > 95 %, FPR < 1 %) | PASS |

## Operational numbers from the same run

| | |
|---|---|
| latency p50 / p95 / max | 9.2 ms / 44.6 ms / 72 ms (deadline 5 s) |
| cgroup memory peak | 497 MiB of 1 GiB, oom_kill 0 |
| worker processes | spawned 3, recycled 2 (planned recycling), died 0, killed_overrun 0 |
| sha256 of every POSTed body vs manifest | 100/100 match |

## Verification (workflow `course-set-metrics-v33`, run wf_d0d45064-8bc)

Three independent verifiers tried to refute the table, none did:

- **Definitions/arithmetic:** every cell recomputed with exact fractions and with scikit-learn;
  one-vs-rest convention for the goodware FPR confirmed as sklearn's per-class view.
- **Provenance:** 100 rows, sha256 set equals the manifest, all HTTP 200 `application/json`
  integer answers, none late; image id matches `mlsec-defender:v33-fromzip`, whose BuildKit record
  embeds a Dockerfile byte-identical to the zip's. Caveat: the `-m 1g --cpus 1 --read-only` flags
  of the removed container rest on the recorded command text (Docker keeps no HostConfig after
  removal); the nine earlier container gates used the same flags through `container_gate.sh`.
- **Independent recompute + reconciliation:** scikit-learn 1.9.1 from the per-sample rows gives
  identical values to 6 decimals; all 11 recorded v3.3 matrices (in-process JSON, nine container
  gate logs) are byte-verified and agree.

## What these numbers do and do not say

With a perfect confusion matrix every metric is degenerate (1 or 0); the table proves the detector
clears the course bar on this set, not how it generalises. The honest generalisation numbers are the
ones measured on data the course set never touched: grouped 10×5 CV and the sealed holdout goodware
FPR of 50/591 (V33_STATUS.md), and the 7-attack robustness suite. The hidden grading set is not
guaranteed by any of this.
