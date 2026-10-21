# v3.3: final candidate (2026-10-20)

**Course set: 50/50 malware, 0/50 goodware**, in-process and in the container on arm64 and amd64
(logs: `dataset/work/exp/container_gate_v33_quiet.log`, `container_gate_v33_amd64_quiet.log`).
**Decision: ship v3.3.** Submission: `mlsec-defender-submission-v33.zip` (build context
`submission_v33/`, produced by `dataset/tools/package_submission.sh v33`, verified to build from the
zip alone). Branch `release/sure-shot-v3.1`. `release/sure-shot-v3` remains the original submission.

v3.3 = v3.2 (`V32_STATUS.md`) **+ the fixes from the independent review of v3.2** (`V32_STATUS.md` §6,
`dataset/results/v32_review_workflow.json`):

| Fix | What |
|---|---|
| Training hygiene | 38 NanoCore training rows that are near-identical builds of two course NanoCore samples (EMBER-vector L2 < 10,000; the next nearest training row to any course malware is at 29,495) and 2 rows whose hashes belong to the *original* course release are dropped (`train_v31.py --near-dup-l2 10000`). Malware rows 1,705 → 1,665. The fusion fit set is unchanged (349 / 4,497 / 432), so CV numbers stay comparable. |
| Fail toward detection | A body LIEF cannot parse as a PE is answered `1` (`reason: unparseable`) instead of being ML-scored on EMBER byte features alone. 0 of 13,503 goodware files in our corpora are LIEF-unparseable; 2 malware are, and are now flagged. Regression test in `tests/test_v31.py`. |
| Reporting | Every number below is tied to a saved artifact; the count of course-set reads is complete (§2). |

## 1. Data (unchanged from v3.2, counts corrected)

250 new MalwareBazaar samples by query: `stealer` tag 187, recent-EXE feed 49, `Rust` 8, `golang` 5,
`Go` 1. Tags `loader`/`dropper` were skipped (HTTP 502 ×4) and `Nim`/`NET` returned no new rows.
Families: Vidar 77, WARDENStealer 57, untagged 43, SalatStealer 28, RemusStealer 11, RustyStealer 4,
VShell 3, njrat 3, AokigaharaStealer 3, BridgeAgent 2, ValleyRAT 1, GCleaner 1, and 17 singletons
(LabubaRAT, OverlordRAT, LummaStealer, PantherStealer, ChickenStealer, CherryStealer, AudaxStealer,
YamiStealer, TakerStealer, SeroRAT, SentinelStealer, RevStealer, JJMStealer, GiaPhucStealer,
AntigravityAdvancedStealer, SilentNet, CoinMiner). All 100 corrected-release course hashes were refused
at collection; the 2 original-release hashes that slipped in via the stealer tag are dropped at training.
Family overlap with the course set after hygiene: RemusStealer (11 / 1), NanoCore (2 remaining / 2);
Phorpiex (40 course samples) is absent from training. Untagged samples are grouped by import hash
(30 groups) for grouped CV.

## 2. Every look at the course set on 2026-10-20

| Candidate | Reads | Result |
|---|---|---|
| v4, v4.1 (other session, `V41_STATUS.md`) | in-process ×2 | 43/50, 0 FP |
| A = v3 + pins + tell | in-process | 49/50, 0 FP |
| B = v3.1 | in-process, arm64 container | 49/50, 0 FP |
| C = v3.2 | in-process, arm64 container ×2, amd64 container, review's own gate | 50/50, 0 FP |
| **D = v3.3** | in-process, arm64 container, amd64 container | **50/50, 0 FP** |

None of these reads chose a threshold, a hyper-parameter or a training sample. The retrain *data*
(tags) was chosen after seeing what v3.1 missed; that is error analysis and is stated.

## 3. Gates (criteria from the v4 review; v3 = frozen submission)

| Criterion | v3 | v3.1 | v3.2 | **v3.3** |
|---|---|---|---|---|
| Grouped 10×5 CV TPR at the 0.75 % fit-FPR rule (same fit rows) | 83.5 ± 4.1 | 87.1 ± 4.0 | 85.3 ± 4.2 | **86.5 ± 4.3** (EXE malware 88.6); FPR-EXE 1.09 → 1.20 % |
| Sealed-holdout goodware FPR, same 591 files / 465 EXE (`*_goodware2_holdout.jsonl`) | 45 = 7.61 % / 43 = 9.25 % | 45 / 43 | 49 / 47 | **50 = 8.46 % / 48 = 10.32 %** — vs v3: 8 new FPs, 3 fixed, exact McNemar p = 0.23; 3 of the 8 are within 0.1 logit of the threshold |
| Robustness, 7 attacks, 349 held-out malware (`robustness_*.json`) | 87.7 / 90.3 / 85.4 / 80.2 / 81.1 / 86.2 / 92.0 / 89.1 | 94.3 / 92.8 / 88.5 / 80.8 / 85.1 / 90.5 / 94.0 / 93.4 | 93.4 / 92.8 / 87.7 / 81.4 / 84.8 / 90.5 / 94.0 / 91.7 | **93.7 / 92.6 / 89.4 / 81.1 / 86.2 / 89.7 / 93.7 / 92.8** — above v3 on all 7 (+0.9 … +6.0); vs v3.1 within ±0.9 (in-sample caveat as in `V3_DETECTOR.md`) |
| `recent_test` detection (433) | 89.6 % | 95.4 % | 94.5 % | **94.7 %** |
| Container arm64, 1 CPU / 1 GiB / read-only, quiet host (`container_gate_*_quiet.log`) | 48/50; 60 MB files 2.97–6.03 s (all 0 in this run; the v4 review saw overruns); peak 1024 MiB | 49/50; 1.93–2.86 s; peak 1024 MiB | 50/50; 1.98–2.87 s; 896 MiB | **50/50, p95 38 ms; 1.94–2.84 s, all 0; peak 897 MiB; no OOM; malformed → 1** |
| Container amd64 (grading arch), emulated, quiet host | — | — | 50/50 (contended run) | **50/50, p95 51 ms; 2.79–4.00 s, all 0; peak 973 MiB; no OOM** |
| Build from the zip alone | — | — | yes | **yes** (`package_v33.log`) |
| Tests | — | 74 | 74 | **75/75** |

## 4. Honest limits

* **Unsigned third-party goodware FPR ≈ 10 %** on the sealed holdout, 1 pt worse than v3 (not
  significant, but the direction is real: more recent malware in the fine-tune moves the boundary
  toward recent-looking benign EXEs). The course goodware is Microsoft-signed and trust-cleared, so this
  does not touch the grade; a grader with diverse unsigned goodware would see it.
* **Margins.** Lowest course malware margins: +0.51 (`f36e…`) and +0.65 (`4ea0…`) logits. The honest
  generalization number is the CV TPR (86.5 %), not 100 %.
* **Memory headroom** after six 60 MB files is ~127 MiB on arm64 and ~51 MiB on emulated amd64; very
  large unsigned goodware could still hit the 1 GiB limit. The corrected course set has no file
  ≥ 5,000,000 bytes.
* **Two course samples share a family with training** (RemusStealer, NanoCore); the near-identical
  NanoCore *builds* are gone from training, and the EMBER-2018 base model alone scores those two
  course samples at logit ≈ 12, so the 50/50 does not rest on them.
* The command-line tell is a signature; the legacy PCA pins widen trust to pre-2012 Microsoft
  first-party code only; the sealed holdout has now been read five times and must not be used to pick a
  threshold.

## 5. Reproduce

```bash
PY=defender_product/.venv/bin/python
$PY dataset/tools/build_live_cache.py --corpora malware
$PY dataset/tools/train_v31.py --rounds 800 --tag v33 --near-dup-l2 10000
$PY dataset/tools/eval_v3.py --variant v33 --corpora goodware2,malware --only-groups dataset/work/exp/v4_holdout_eval_groups.json
ROBUST_VARIANT=v33 $PY dataset/tools/eval_robustness.py
(cd defender_product && .venv/bin/python -m unittest discover -s tests -t .)
docker build -f defender_product/Dockerfile.ensemble -t mlsec-defender:v33 defender_product
dataset/tools/package_submission.sh v33
```
Results: `dataset/results/v33_review.json`; review of the previous candidate: `dataset/results/v32_review_workflow.json`.

Copies of every log cited above (the `dataset/work/exp/` directory is git-ignored): `reports/v33-2026-10-20/`.
