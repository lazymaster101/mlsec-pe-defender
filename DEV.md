# dev/v4: development branch (built on top of `release/sure-shot-v3`)

Branch policy:
- `release/sure-shot-v3` is **frozen**. It holds the verified PASS submission; see
  `SURE_SHOT.md`.
- All new work lands here, on `dev/v4` or on branches cut from it.
- A change is promoted to a new `release/*` branch only after it passes the same gates as
  v3: grouped-CV gain, no robustness regression, ARM64 + x86-64 container verification,
  and a single post-freeze run on the course set.

## Status (2026-10-19)

v4 and v4.1 candidates trained and reviewed: both **NO SHIP**. See `dataset/docs/V4_STATUS.md`
and `dataset/docs/V41_STATUS.md`. v4.1 passes 4 of 5 pre-registered criteria (leak-free,
holdout EXE FPR 0.43% vs v3 9.25%, container gates, +12.8 pts grouped-CV TPR at matched
FPR) and fails only robustness-at-deployed-thresholds, which turned out to compare
operating points set on different calibration populations, not detectors. Any v4.2 must
first amend that criterion openly (matched calibration) before running.
- Large real gain: unsigned third-party goodware EXE FPR on a sealed 291-product holdout
  dropped from 9.2% (v3) to 0.65% (v4); +12.9 pts grouped-CV TPR at matched FPR.
- Blocked by a robustness regression at deployed thresholds, and by a minor leak (fixed in
  code, retrain pending).
- The container OOM found in review is already fixed.
- `Dockerfile.ensemble` still serves v3. The v4 artifacts are committed as a candidate
  (`models/rf_v4`, `models/ember_ft_v4`, `models/fusion_v4.json`).

## Layout

| Path | What |
|---|---|
| `defender_product/` | Source of truth for the detector: `defender/`, `tests/` (45 tests), `Dockerfile.ensemble`, models. `submission/` is a copy of it. |
| `dataset/tools/build_live_cache.py` | Extracts serving-identical features, scores and Authenticode facts for every corpus into `dataset/work/live_cache/`. Never executes samples. |
| `dataset/tools/train_v3.py` | Trains `ember_ft`, fits the log-odds fusion and fallbacks on out-of-fold scores, and writes the CV estimate into `fusion.json`. |
| `dataset/tools/exp_*.py` | E2 byte-slice model (rejected), E4 fine-tune, E5 fusion forms, E6 three-member stack. |
| `dataset/tools/eval_v3.py`, `eval_robustness.py`, `grade_http.py` | End-to-end, in-memory problem-space robustness, and HTTP grading harnesses. |
| `dataset/docs/V3_DETECTOR.md`, `PAPER_CONCEPTS.md` | Design, honest metrics, and the concept map of all 26 course papers. |

Data (`dataset/raw`, `quarantine`, `goodware`, `work`, `models`) is git-ignored: it holds
malware and large corpora.

## Reproduce v3 from data

```bash
python dataset/tools/build_live_cache.py --corpora course,malware,goodware,local
python dataset/tools/train_v3.py            # prints the 10x5 grouped-CV estimate
cd defender_product && python -m unittest discover -s tests -t .
```

## v4 backlog (ranked; see `dataset/docs/V3_DETECTOR.md` §5)

1. Grow native-EXE goodware past 2,000 files from at least 300 products. This needs
   download approval.
2. Retrain rf_adv with live goodware. Its remaining FPs are Go binaries and Python launchers.
3. Few-shot and learning curves on a time split, then targeted malware-family collection.
4. An EMBER2024 member with a matching extractor. This needs download approval.
5. A VirusTotal hash-only label audit of the top-scoring goodware and lowest-scoring
   malware.
