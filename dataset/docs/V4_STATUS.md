# v4 candidate: status after review (2026-10-18)

**Decision: NO SHIP.** `release/sure-shot-v3` remains the submission.

The v4 artifacts (`rf_v4/`, `ember_ft_v4/`, `fusion_v4.json`) are committed on `dev/v4`
as a candidate only. `Dockerfile.ensemble` still serves v3 by default.

## What v4 is

- **New goodware corpus (`dataset/goodware2`).** 2,118 Windows PE files, 1,615 of them
  EXEs, from 966 products. Sources: GitHub releases found by search across 30
  language/domain queries, and Chocolatey vendor downloads. Collection was static only:
  nothing was installed or executed. Label hygiene:
  - deny-list for RAT/C2/crack/cheat/miner repos;
  - 20 files whose hashes are in the course grading set were dropped automatically;
  - 11 Sysinternals products, which are other versions of the grading-set goodware, are
    excluded from everything;
  - the Defender-remover tool is excluded as greyware.
- **`rf_v4`.** The rf_adv recipe plus about 11k live-extracted goodware rows, weighted to
  balance classes within each file-type stratum. Diagnosis behind it: rf_adv's live rows
  were 1,021 malware against 140 goodware, so it learned "freshly extracted ⇒
  malicious". That is why it flagged Go binaries at r ≈ 0.97.
- **`ember_ft_v4` and `fusion_v4`.** Refit on the larger, harder development pool.
- **Serving code (pure refactors; identical outputs verified on 571 files end to end and
  500 files for strings):**
  - LIEF parses each file once instead of three times;
  - EMBER string features are about 1.5× faster on large files.

## Review (5-agent workflow: integrity, sealed holdout, container, robustness, judge)

| Criterion (pre-registered) | Result |
|---|---|
| Grouped-CV TPR gain at matched EXE FPR | **MET.** On identical rows, folds and rule: v3 recipe 62.5% vs v4 75.4% TPR at about 0.98% EXE FPR. All 50 paired folds favour v4; family-cluster bootstrap +7.8 to +18.3 pts. |
| Sealed-holdout goodware FPR (291 unseen products, 465 EXE) | **MET.** v3 flags 43/465 = **9.2%**; v4 flags 3/465 = **0.65%** (Wilson 0.22–1.88%). Paired McNemar p = 1.8e-12. |
| No leakage | **FAILED, minor.** The 140 recent_train goodware rows bypassed the holdout filter, putting 4 holdout products (6 files) into rf_v4 training; 7 more products appeared under two names (choco vs github). The holdout result is unchanged without them (43/461 vs 3/461). **Fixed in code:** recent_train goodware dropped (it duplicates corpus rows) and a canonical product key added. Not yet retrained. |
| Robustness: no attack loses more than 5 pts vs v3 | **FAILED.** At the deployed thresholds v4 loses 5.4–9.2 pts on 6 of 7 in-memory attacks (overlay 1–4 MB, 10k strings, section inject, cert blob). Part of this is the operating point: v4's threshold is calibrated on harder goodware, and at matched holdout FPR v4 beats v3 on every attack. Part is real: v4's drop from its own clean TPR is larger. |
| Container gates (arm64 + amd64, 1 CPU, 1 GiB) | **FAILED, then fixed.** The vectorized string code OOM-killed the server on 60–67 MB benign files. Replaced with a lean version: identical output on 500/500 files; under `-m 1g` the 6 largest files return 0 in 1.7–2.7 s, cgroup peak 956 MiB, no OOM. A memory regression test was added. |

## Findings that matter beyond v4

- **v3 false-positive rate.** v3 (the sure-shot) flags **about 9% of unsigned third-party
  goodware EXEs**, measured on the sealed holdout. Its earlier 1.1% EXE-FPR estimate came
  from a goodware pool that was too easy. It passes the course set because that goodware is
  Microsoft-signed (Sysinternals), which the trust layer clears.
- **v3 latency and memory on very large files.** On 60+ MB files the frozen v3 code takes
  2.6–3.4 s per file in the container, and its cgroup memory peak reaches the 1 GiB limit.
  It survives, but with little headroom. Course-set files are small.

## Next (v4.1), each change re-gated by the same review

1. Retrain rf_v4 with the leak fix and canonical product keys. Drop the 11 alias-contaminated
   products from the holdout evaluation list.
2. Attack-aware training for ember_ft: add in-memory overlay, string and section variants of
   training-fold malware, labeled malicious (Lucas et al., "train on the attack"). This
   targets the measured fragility.
3. Re-check the operating point. Report robustness both at deployed thresholds (the
   pre-registered criterion, unchanged) and at matched FPR (diagnostic).
