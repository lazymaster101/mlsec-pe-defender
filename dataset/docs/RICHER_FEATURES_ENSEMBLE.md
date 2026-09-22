# Richer features + diversified ensemble — results and honest caveats

Follow-on to [SOTA_RESEARCH.md](SOTA_RESEARCH.md): breaking the ~80% ceiling of the NFS
hashed feature space by moving to EMBER's 2381 rich features, and combining the result
with the hardened NFS model as a diversified ensemble. Every number here was measured;
where a result is fragile or was inflated by a bug, it says so.

## 1. The ceiling was the feature space, not the algorithm

Trained LightGBM on EMBER's full 2381-dim features (byte histograms, byte-entropy,
string stats, header/section/import/export/data-directory groups), on the **same** train/
test samples our RF models used (matched by SHA-256):

| Model | Feature space | EMBER-test TPR@1%FPR | TPR@0.1%FPR |
|---|---|---|---|
| supplied | NFS 250k-hash | 71.2 % | — |
| `rf_augmented` | NFS 250k-hash | 79.5 % | ~40 % |
| `rf_adv` (deployed) | NFS 250k-hash | 76.7 % | ~40 % |
| **`ember_gbdt`** | **EMBER-2381** | **93.7 %** | **~82 %** |

A **+17-point** jump at 1 % FPR (and far larger at the strict 0.1 % point production
uses), at <60 MB and millisecond inference. Confirmed: the NFS ceiling was the *clues*,
not the learner. Tools: `tools/train_ember_gbdt.py`, `tools/ember_compat.py` (runs the
EMBER extractor on modern lief-0.17 / numpy-2).

## 2. A deployment bug we caught (and it is a classic pitfall)

The first attempt to add recent MalwareBazaar malware to the richer model **broke
goodware**: 6/7 known-safe programs scored as malware. Cause: EMBER training features
come from the old lief-0.9 JSONL, but recent malware could only be extracted **live**
with lief-0.17 — so *every* malicious recent sample went through the live pipeline and
*every* benign sample through the old one. The model learned the shortcut
**"live-pipeline → malicious"** (Arp P4 spurious correlation / Ceschin feature-extractor
drift). Caught by validating on real goodware, not the EMBER-internal FPR.

**Fix attempted:** harvest a live-extracted benign corpus so both classes appear in both
pipelines. Three sources: Chocolatey (212 — exhausted), NuGet (4,000 — but 93 % managed
.NET DLLs), GitHub releases (1,378 native). Even with ~5,600 live benign, the single
richer model **still failed to generalize**: held-out goodware not in the harvest
false-positived (e.g. `wmplayer.exe` 0.003 → 0.906 once recent malware was mixed in).
Our live benign corpus cannot match EMBER's benign scale/diversity, so mixing pipelines
in one model is not reliable. **Lesson recorded, not papered over.**

## 3. The fix that works: a diversified ensemble

`ember_gbdt` (EMBER-only, one uniform pipeline — **generalizes**: all 7 held-out native
EXEs score ~0) **OR** `rf_adv` (NFS, recent + hardened). Each scores through its own
pipeline, so there is no cross-pipeline confound. Flag malicious if either exceeds its
threshold; thresholds jointly calibrated to **1 % combined FPR** on 807 held-out goodware
(in neither model's training). Tools: `defender/ensemble.py`, `tools/ensemble_eval.py`.

| At 1 % FPR (807 held-out goodware) | Recent-malware detection (held-out) |
|---|---|
| `rf_adv` alone | 80.8 % |
| `ember_gbdt` alone | 90.3 % |
| **ensemble (OR)** | **90.5 %** @ 0.99 % FPR |

Under an overlay-append disguise (+100 KB benign): ensemble **88 % → 90 %** (holds;
rf_adv's NFS features ignore overlay bytes, ember_gbdt is also robust to this one).

## 4. Honest caveats

* **Recent-detection numbers are calibration-set sensitive.** The same `ember_gbdt` reads
  51 % recent when calibrated on a small native-heavy goodware set and 90 % on the broad
  807-file set — because the threshold placement moves a lot and recent-malware scores
  are spread. Report the calibration set with any number.
* **The ensemble's *clean* gain over `ember_gbdt` alone is marginal** (90.5 % vs 90.3 %);
  ember dominates. The ensemble's real value is diversification — an independent second
  model (rf_adv) that fails differently, plus rf_adv's overlay-immunity and its
  adversarial hardening (COMPARISON §10).
* **`ember_gbdt` uses a train/serve `lief`-version skew** (trained on lief-0.9 EMBER
  vectors, served via lief-0.17). Validated tolerable end-to-end (native goodware ~0,
  malware well-separated), but it is a known, documented approximation, not bit-exact.
* **Still one stratum, still evadable in the limit** (SOTA_RESEARCH §0): a determined
  attacker who forges every feature wins; this is defense-in-depth, not an oracle.

## 5. Status

Built and validated: `ember_gbdt` model, the ensemble scorer (`defender/ensemble.py`),
and the operating point (`dataset/results/ensemble_operating_point.json`). Deployed
container still ships the hardened `rf_adv`; **containerizing the ensemble** (dual
pipeline + ember/lightgbm/lief/sklearn deps) is the remaining step.
