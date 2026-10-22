# Retraining and industry comparison: MLSEC PE defender

Compares the supplied *Need For Speed* (NFS) random forest against models
retrained on a representative, temporally-ordered dataset, under the threat model
in [THREAT_MODEL.md](THREAT_MODEL.md). Dataset construction is in
[DATASHEET.md](DATASHEET.md). All raw results are in `dataset/results/*.json`.

## TL;DR

1. The supplied model's problem is **not discrimination** (ROC-AUC 0.976) — it is
   **calibration**: at its shipped 0.25 threshold it produces **12.8 % false
   positives**, far outside the 1 % budget.
2. Retraining with a **correctly configured** RandomForest beats it on every axis
   that matters: **77.9 % vs 71.2 % TPR at 1 % FPR**, equal AUC, while **9× smaller**
   and **1.8× faster**.
3. The naive retrain (scikit-learn defaults) is *worse* (58.7 %) — a documented
   trap, not a modelling dead end (see §4).
4. **No model tried reaches 95 % TPR at 1 % FPR** on this feature space (one RF
   family and one aborted LightGBM run, §6). The richer EMBER feature set reaches it
   (§6, 93.8 %); whether the NFS 250k-hash space itself forbids 95 % is not established,
   only that these models did not get there.
5. On **recent 2020–2026 malware**, every model **collapses to AUC ≈ 0.79** —
   concept drift is real and large, and is the dominant deployment risk (§5).

## 1. Metrics and why

Graded at **FPR ≤ 1 %, TPR ≥ 95 %**, so the headline is **TPR at the threshold
where FPR = 1 %**, with a 95 % Wilson interval. Accuracy and F1 are omitted: at
realistic base rates they track the majority class and hide the graded trade-off.
ROC-AUC is reported only as a threshold-free summary.

Two evaluation sets: the **EMBER 2018 temporal test** (months 2018-11/12, held out
— large, in-distribution, tight intervals) and a **recent drift set** (real
2020–2026 MalwareBazaar malware + current Chocolatey goodware — the honest test of
threats appearing after training).

## 2. Models

| Name | Model | Training data | Feature space | Nodes | Artifact |
|---|---|---|---|---|---|
| `supplied` | RandomForest | ~1.8M samples through 2020 (given) | NFS 250k | 14.15M | 398 MB |
| `retrained_rf` | RandomForest, sklearn defaults | EMBER train <2018-11, 300k | NFS 250k | 409k | 13 MB |
| `rf_tuned` | RandomForest, `max_features=0.05` | EMBER train <2018-11, 300k | NFS 250k | 1.60M | 47 MB |
| `rf_augmented` | `rf_tuned` + 1,021 recent (2020–26) | EMBER + recent | NFS 250k | 1.63M | 48 MB |

All share the NFS feature space, so differences isolate *data* and *configuration*,
not feature engineering.

## 3. EMBER 2018 temporal test — 25,000 benign / 25,000 malicious

| Model | ROC-AUC | TPR @ FPR=1% | 95% CI | FPR @ 0.25 | TPR @ 0.25 | ms/sample |
|---|---|---|---|---|---|---|
| supplied | 0.9762 | 0.712 | [0.706, 0.717] | 0.128 | 0.954 | 3.39 |
| retrained_rf | 0.9362 | 0.587 | [0.581, 0.593] | 0.538 | 0.983 | 1.96 |
| rf_tuned | 0.9766 | 0.779 | [0.773, 0.784] | 0.232 | 0.972 | 1.91 |
| **rf_augmented** | **0.9765** | **0.799** | [0.794, 0.804] | 0.237 | 0.972 | 1.90 |

`rf_augmented` is the best model here: **+6.7 points of TPR at the 1 % operating point**
over the supplied model (79.9 % vs 71.2 %), identical AUC, at ~1/9 the size and ~half
the latency. Adding the recent samples did not cost anything in-distribution.
The shipped 0.25 threshold is shown only to expose the calibration problem — none
of these models should be run there.

## 4. Why the naive retrain fails (and the fix)

The NFS feature space is 250,036 columns, of which only 22 are dense numeric header
fields; the rest are sparse hashed text. scikit-learn's default
`max_features="sqrt"` (≈ 500 columns per split) sees a dense column in only **4.3 %**
of split attempts, so trees split mostly on near-empty hashed columns and underfit.
Raising `max_features` to 0.05 (12,500 columns; a dense column visible in ~68 % of
split attempts — 1 − (1 − 12,500/250,036)^22 ≈ 67.6 %, exact hypergeometric 67.64 %; an
earlier version of this sentence said 99.99 %, which was an arithmetic error) is the
entire difference between 58.7 % and 77.9 %. The single-draw probability is an
approximation of scikit-learn's actual split search, which also tries further columns
when the drawn ones yield no valid split. This is a representation/hyperparameter
interaction, documented so it is not repeated.

## 5. Recent drift — 1,455 malware (2020–2026, 38 families) / 200 goodware

| Model | ROC-AUC | TPR @ 0.25 | TPR @ 0.5 | goodware FPR @ 0.25 |
|---|---|---|---|---|
| supplied | 0.7993 | 0.612 | 0.345 | 0.190 |
| rf_tuned | 0.7812 | 0.691 | 0.412 | 0.300 |

Both **collapse from AUC ≈ 0.976 to ≈ 0.79**. At the 1 %-FPR threshold calibrated on
2018 data, whole 2023–2026 families are missed entirely — supplied scores
AsyncRAT, CobaltStrike, GuLoader, BumbleBee, CoinMiner, QuasarRAT, Matanbuchus at
**0 %**. This is concept drift (threat model §5), and it is the single most
important operational result here: **a static model must be retrained on current
data on a schedule**, and its threshold recalibrated with it. `rf_augmented` (§7)
tests whether adding the collected recent samples helps.

## 6. Industry reference

EMBER's published gradient-boosted detector (Anderson & Roth, 2018) reports
ROC-AUC ≈ 0.9991 and ≈ 92.9 % TPR at 0.1 % FPR on its 2018 test set — but over a
**2,381-feature** space (byte histograms, byte-entropy, string statistics) and
1,000 trees, i.e. signal the NFS feature set does not contain. Attempting a
gradient-boosted model *inside* the NFS space was tried and rejected: LightGBM
builds per-feature histograms, so 250k features made a single training run exceed
40 minutes without completing 100 rounds, and reducing the hash width to make it
tractable dropped TPR@1%FPR to 0.42–0.47 (the hashed import signal does not survive
the collisions). The gap between EMBER's number and ours (§3) was attributed here to the
1 GB / 5 s deployment budget the NFS feature set was chosen for. **Erratum (2026-10-21):**
that attribution was wrong. The EMBER-2381 LightGBM member was later served inside the
same budget (~0.5 ms per feature vector; live p95 56 ms, a 33 MB file in 1.43 s on one
CPU — [RICHER_FEATURES_ENSEMBLE.md](RICHER_FEATURES_ENSEMBLE.md) §6, [V3_DETECTOR.md](V3_DETECTOR.md)),
so the budget never excluded richer features; this section only shows that the models
tried on the NFS hashed feature space stopped at ~80 %, and that EMBER-2381 went further.

## 7. Does adding the collected recent malware help?

`rf_augmented` = `rf_tuned` training data + 1,021 held-in recent malware (2020–2026),
evaluated on **493 held-out recent samples the model never saw** (433 malware /
60 goodware), family-stratified so train and test families overlap but instances
do not.

| Model | recent-test ROC-AUC | recent-test TPR @ 0.25 |
|---|---|---|
| rf_tuned (EMBER only) | 0.820 | 0.695 |
| **rf_augmented (+recent)** | **0.937** | **0.988** |

Adding 1,021 recent samples lifted held-out recent detection from 69.5 % to
**98.8 %** at 0.25, with **no** loss on the EMBER temporal test (AUC 0.9765 vs
0.9766). **Caveat:** the recent train/test split is family-stratified, so this
measures detection of *new instances of families seen in training*, not
generalisation to unseen families — which is exactly how scheduled retraining
works in practice, and is not a claim of zero-day coverage.

### The result that matters most — recent detection at the deployed threshold

At the single deployed threshold (0.7565, = 1 % FPR on EMBER benign), over the full
recent set (1,455 malware 2020–2026 / 200 goodware):

| Model | recent-malware caught | recent-goodware FPR |
|---|---|---|
| supplied | **9.2 %** | 0.5 % |
| rf_tuned (EMBER only) | 12.0 % | 0.0 % |
| **rf_augmented (+recent)** | **75.3 %** | 2.0 % |

The goodware column pools all 200 recent goodware. For `supplied` and `rf_tuned`, which
never saw them, that is a measurement; for `rf_augmented` (and `rf_adv`), 140 of the 200
are *training* rows and only the 60 held-out rows measure anything (`rf_adv`: 1/60 =
1.7 %, Wilson 95 % 0.3–8.9 %; 0/140 on its own training rows). n = 60 cannot certify a
1 % population FPR either way (review 2026-09-21, finding 6).

The supplied model, at a sane 1 %-FPR threshold, catches **9 % of current malware** —
it is effectively blind to the present threat landscape. Retraining with the
collected samples raises that to **75 %**, holding 58–83 % across every year from
2020 to 2026 (2026: 77 %). This is the concrete payoff of the dataset work.

## 8. Deployment recommendation

**Deploy `rf_adv`** — `rf_augmented`'s training data *plus* 90,612 synthetic
feature-space perturbations of training malware rows (attribute-dict edits; no PE is
produced; RandomForest, `max_features=0.05`), at **threshold 0.8209**. That threshold
was chosen to give exactly 1 % FPR (300/30,000) on a 30k/30k *subsample of the EMBER
test file* (`operating_point.json`), so 1 % is a calibration fit, not a bound: on all
100,000 test benign the same threshold gives **1.051 %** (1,051; Wilson 95 % 0.99–1.12 %),
and **1.073 %** on the 70,000 benign outside the calibration subsample (review
2026-09-21, finding 1). The clean `rf_augmented` remains in the repo
(`dataset/models/nfs_rf_augmented`) for the clean-only comparison; it is **not** in the
image, which copies only `rf_adv`. The full robustness analysis is §10 (feature-space).

*2026-10-21:* the course submission is no longer this single-model image but the v3.3
ensemble ([V33_STATUS.md](V33_STATUS.md)), whose decision thresholds are fit on separate
folds and reported by grouped CV and a sealed holdout; `rf_adv` enters it only as a
continuous member and the 0.8209 threshold is not used there.

At that operating point:

All numbers here share the §10 evaluation basis (held-out `recent_test`, deployed
threshold); the clean-model baseline for the delta is `rf_augmented` on the *same*
evaluation (79.5 %), not §3's separate 25k/25k number (79.9 %).

| | value |
|---|---|
| EMBER temporal TPR @ 1 % FPR | 76.7 % on the 30k calibration subsample; **76.73 %** (76,728/100,000) on the full test at the fixed threshold (`rf_augmented` 79.5 %, supplied 71.2 %) |
| held-out recent detection (clean) | 59 % = 254/433 (`rf_augmented` 66 %; supplied ~9 %); 53 % on the 349 rows with no feature-identical training twin |
| held-out recent under the combined feature-space perturbation C | **55 %** (`rf_augmented` 7 %) |
| goodware FPR | EMBER: 1.00 % on the 30k calibration subsample, **1.051 %** on all 100k test benign (Wilson 0.99–1.12 %); recent: **1/60 held-out** (1.7 %, Wilson 0.3–8.9 %), 0/140 trained-on |
| model artifact | 59 MB, 2.04 M nodes |
| container memory (`docker run -m 1g`) | 147 MiB (14 %) |
| latency through live HTTP | mean 13 ms, p95 48 ms, max 66 ms (budget 5 000) |
| image size | 388 MB |

Verified in the running container (`mlsec-defender:adv`, `docker run -m 1g`): **0/7
goodware false positives**, 37/50 recent malware malicious over the live HTTP path,
and malformed input (random / truncated / empty) all fail to `1`. The image ships
`rf_adv` as the default (`DF_MODEL_DIR=/app/models/rf_adv`,
`DF_MALWARE_THRESHOLD=0.820932`).

**The trade-off, stated plainly.** Adversarial training costs **2.8 points** of clean
EMBER TPR (79.5 → 76.7) and ~7.6 of clean held-out recent detection (66 → 59), and in
return roughly **8×** the detection of malware rows cheaply perturbed with a
*trained* perturbation family (combined perturbation C 7 → 55 %, §10). It does **not**
buy robustness to an untrained mechanism (§10, F) or to full feature mimicry (D), and
none of it was verified with executable adversarial binaries (§10). For a detector whose
threat model is a white-box evader (THREAT_MODEL §2–§3), raising the cost of the cheap
perturbations is a reasonable trade. (`rf_augmented` is not in the image; switching
means rebuilding with its arrays and `DF_MALWARE_THRESHOLD=0.756536`.)

**Honest bottom line vs the challenge goals.** The 1 % FPR target is met on the
calibration subsample by construction of the threshold and is **not** a bound beyond it:
1.051 % (Wilson 0.99–1.12 %) on the full EMBER test benign, 1.073 % outside the
calibration subsample, 1/60 on held-out recent goodware. The 95 % TPR bound is **not**
reached in the NFS feature space (best 79.5 % clean at 1 % FPR); closing that gap needs
richer byte/string features (§6), which were later shown to fit the budget
([RICHER_FEATURES_ENSEMBLE.md](RICHER_FEATURES_ENSEMBLE.md)). What this work fixes are
the real defects: a 13 % → ~1 % FPR recalibration, 9 % → 59 % (`rf_adv`; 66 % for the
clean `rf_augmented`) recent-threat detection on held-out malware, and 7 % → 55 %
detection under a synthetic feature-space evasion (not an executable one).

## 9. Threats to validity

* Goodware in the drift set is 200 popular free-software PEs — a spot check, not a
  population FPR; the large-sample FPR is the EMBER 100k-benign number.
* MalwareBazaar family coverage is an availability sample.
* The `rf_augmented` test set is small (493); its interval is correspondingly wide.
* **Feature-space robustness was measured (negative) and then mitigated in feature
  space.** Against the clean `rf_augmented`, synthetic edits to the attribute dicts of
  the exact fields this feature space reads (append benign "dead" imports; rewrite
  mutable header metadata) drop recent-malware detection from 75 % to **9 %** — back to
  the un-retrained level. The deployed `rf_adv` is trained with random augmentation on
  the same perturbations (unguided; not Lucas et al.'s attack-based training) and lifts
  the combined perturbation to **55 %** on held-out rows, at a 2.8-point clean-TPR cost —
  but gains nothing against an untrained mechanism (F) or full mimicry (D). **No PE was
  rewritten, validated or executed for any of these numbers**, so they say nothing about
  executable adversarial binaries or an adaptive attacker (review 2026-09-21, finding 3). §10 /
  [PITFALL_AUDIT.md](PITFALL_AUDIT.md) Part 2;
  raw numbers in `dataset/results/adversarial_featurespace.json` (attack on the clean
  model) and `adversarial_training.json` (clean vs hardened).
* **The recent-test headline was inflated by feature-level leakage.** ~18 % of
  recent-test malware is feature-identical to a training row (distinct SHA-256, same
  extracted features); the family split isolates hashes, not features. Honest
  novel-feature detection at the deployed threshold is **~60 %**, not the 98.8 % @ 0.25
  quoted in §7 (0.25 is not an operating point — benign FPR there is 48 %). See
  PITFALL_AUDIT.md Part 6 / `pitfall_checks.json`.
* **At realistic base rates, precision is low.** At a 1 % malware base rate the model's
  alerts are majority false positives (PPV ≈ 28–45 %); 1 % FPR is still high for a
  low-base-rate stream (base-rate fallacy, PITFALL_AUDIT.md Part 2).

A full per-paper pitfall audit of this work against all 26 project papers is in
[PITFALL_AUDIT.md](PITFALL_AUDIT.md).

## 10. Adversarial training (the deployed hardening)

The audit (Part 2) showed the clean model is trivially evadable, which is the pitfall
the threat model (§2–§3) and the Shallow-Security / XOR / GAMMA / Lucas papers care
about most. The remedy implemented is **random augmentation with the same synthetic
perturbations**. Lucas et al. (USENIX'23) distinguish exactly this kind of unguided
augmentation from attack-based training on real binaries and show the former is weaker;
an earlier version of this section called it "the Lucas fix", which overstated it.

**Method.** `tools/train_nfs_adversarial.py` takes `rf_augmented`'s training corpus and
adds adversarial malware variants generated by `tools/adv_transforms.py`: for a
fraction (0.6) of the malicious rows, a synthetic perturbation is applied to the
attribute dict (no PE is produced) and the result is kept labelled malicious
(`--adv-mode all`). Rows, donors and transforms are drawn at random — no model query,
loss or gradient. The trained perturbations are intended to mirror realizable
append/rewrite/shrink edits — append benign dead imports (A), rewrite mutable header
metadata (B), both (C), packer-style import-table shrinkage (E) — but that correspondence
is unverified. Reproduce the deployed model exactly with:

```
python tools/train_nfs_adversarial.py --train work/ember_official/train.jsonl \
  --extra-train work/recent_train.jsonl --out models/nfs_rf_adv \
  --max-per-class 150000 --adv-frac 0.6 --adv-mode all
```

**Evaluation is on held-out data** (this was corrected after an audit found the first
pass attacked 70 %-training malware). `tools/evaluate_adversarial.py` attacks the
**held-out `recent_test` split** (n=433, 0 SHA overlap with training) — plus its
novel-feature subset (n=349, features not identical to any training row) — using
**held-out EMBER-test benign as donors**, at each model's **deployed threshold**. So a
gain reflects generalization to new malware *and* new donors, not memorization. Every
rate carries a Wilson 95 % CI. Two attacks are *not* in the training mix: **F**
(section-injection — a held-out *mechanism*, to test transfer) and **D** (full
feature-space mimicry — the unrealizable upper bound).

**Result** (held-out `recent_test`, n=433; % detected, Wilson 95 % CI):

| | EMBER TPR@1 % | recent | recent-novel | A | B | **C** | E‡ | F† | D\* |
|---|---|---|---|---|---|---|---|---|---|
| `rf_augmented` (clean) | 79.5 | 66 [62-71] | 60 [55-65] | 24 | 29 | **7 [5-10]** | 21 | 59 | 0.9 |
| **`rf_adv` (deployed)** | 76.7 | 59 [54-63] | 53 [48-58] | 58 | 59 | **55 [51-60]** | 76 | 58 | 0.9 |

\* D copies *every* model-input feature from a benign donor → both models ~99 % evaded;
the true feature-space ceiling, not problem-space realizable (Pierazzi et al.).
† F (section-injection) is **held out of training**; ‡ E (packing) **is** trained.

**Reading — honestly.** The trained perturbation families are far harder on held-out
rows, with non-overlapping CIs: the cheap combined attack C goes **7 → 55 %** (8×),
packing E **21 → 76 %**. But two caveats the numbers make plain: (1) **F**, a realizable
mechanism the model never trained on, is essentially unchanged (59 → 58 %) — adversarial
training did **not** transfer to an unseen mechanism (though F is itself a weak
perturbation against this import/header feature space); and (2) under the full-mimicry upper bound
**D**, both models are ~99 % evaded — a determined attacker who forges every feature
still wins. So this is in-distribution robustness to the trained attack families on
held-out samples, not general adversarial robustness. The clean cost is **2.8 pt** EMBER
TPR (79.5 → 76.7) and **~7.6 pt** held-out recent detection (66 → 59). `--adv-frac` 0.6
prioritizes robustness per the threat model; lowering it recovers clean recall. Raw
results with CIs: `dataset/results/adversarial_training.json`.

**What §10 does not establish (review 2026-09-21, finding 3).** Every number in this
section is a feature-space result: the perturbations edit extracted attribute dicts, and
no PE was rewritten, parsed back, loaded or executed, so nothing here shows that a working
binary with those features exists, let alone that an adaptive attacker could not find one.
The training was random augmentation, not model-guided attack generation. The byte-level
suite added for v3 (`dataset/tools/eval_robustness.py`: overlay, string, section, header
and certificate edits applied to real PE bytes and rebuilt with LIEF) is closer to the
problem space but still does not execute the result. Claims about executable,
functionality-preserving adversarial binaries await an experiment that produces and runs
them.
