# v4.1 candidate: status after review (2026-10-19)

**Decision: NO SHIP.** `release/sure-shot-v3` remains the submission. v4.1 artifacts
(`rf_v41/`, `ember_ft_v41/`, `fusion_v41.json`) are committed on `dev/v4` as a candidate;
`Dockerfile.ensemble` still serves v3.

## What changed from v4

| Change | Result |
|---|---|
| Leak fix: `recent_train` goodware no longer bypasses the holdout filter; canonical product keys merge choco/github aliases | Integrity **9/9 checks pass**, every row count reproduced from code without training |
| `rf_v41` retrained with the fix | Same gain as before: fold-0 TPR at 1% EXE FPR 69% vs rf_adv 25% |
| Attack-aware `ember_ft_v41`: trained on in-memory overlay/strings/section variants of training-fold malware (5,819 variants, donors disjoint from the evaluation donors) | Member-level goal met: attacked held-out-family variants detected at 0.89–0.92 vs 0.86 clean; relative fragility under the four trained attacks −1.8 pts vs v3's −4.4. **Did not transfer** to the three untrained mechanisms. Clean cost ≈ 0 (control: CV TPR 70.0% without vs 70.2% with) |
| Lean string extractor (the v4 OOM fix) | Container gates **pass** on arm64 and amd64: no OOM, cgroup peak 897 MiB (arm64), largest 67 MB file 2.5 s |

## Review against the pre-registered criteria

| Criterion | Result |
|---|---|
| Grouped-CV gain at matched EXE FPR | **MET**: identical rows/folds/rule, v3 recipe 57.5% vs v4.1 70.2% TPR (+12.8; unanimous across folds) |
| No leakage | **MET** |
| Sealed-holdout goodware FPR | **MET**: EXE 2/465 = **0.43%** vs v3 43/465 = 9.25% (McNemar p = 9e-13); all-file 0.34% |
| Container gates | **MET** (amd64 emulated is near the 4 s budget on 60+ MB files; v3 is worse there) |
| Robustness at deployed thresholds, no attack −5 pts vs v3 | **FAILED on all 7 attacks** (−8.3 to −16.6) and on clean files (260 vs 306 of 349) |

## What the failure actually is

The robustness criterion compares **operating points, not detectors**. Both v3 and v4.1
set their threshold by the same rule (≤0.75% FPR on EXE goodware), but on different
populations: v3 on 432 mostly easy EXEs, v4.1 on 1,445 diverse unsigned ones. v3's
"0.75%" is **9.25%** on the sealed holdout; v4.1's is 0.43%. v4.1 therefore runs ~1.5
logits more conservative and catches less malware at ship time, while at matched FPR it
beats v3 under every attack by +13 to +24 pts (holdout-oracle diagnostic, not shippable).

As written, criteria 3 (holdout EXE FPR ≤ 1.5%) and 4 (no regression versus v3 *at
deployed thresholds*) cannot both be met by any honest detector while v3 is the baseline
at its own threshold. That is a protocol flaw, found by running it, and it can only be
amended openly *before* a next run, not by re-reading the holdout.

## Why v3 still ships, for the grade

The course goodware is Microsoft-signed (Sysinternals): the Authenticode trust layer
clears it identically in every version. v4.1's large FPR gain on unsigned third-party
EXEs therefore buys nothing on the course set, while its more conservative threshold
risks losing one of the 48/50 detections. For a grader using *diverse unsigned*
goodware, the picture would reverse (v3 at ~9% FPR would fail the 1% bar). That is the
real trade-off, and it is the user's call, not a model's.

## Leftovers (all documented, none fixed here)

- The holdout evaluation list still contains 7 alias products (16 files) that favour v3.
- The sealed holdout has now been read for two candidates; a third use to *select* a
  threshold would turn it into a tuning set.
- 30 live goodware files also occur in EMBER-2018 train (negligible; one label conflict,
  `hfs.exe`).
- The robustness suite malware are in-sample for the fine-tune members of every version,
  so only deltas between versions are meaningful there.

## If a v4.2 is wanted

Declare first, then run: compare robustness at a **matched, pre-declared calibration**
(both detectors' thresholds set on the same calibration population), keep the FPR gate on
the goodware2 development pool only, and do not read the holdout again except once for a
final FPR report. Candidate improvements, in order: more unseen-family malware
(few-shot/learning curves on a time split), then an EMBER2024 member.
