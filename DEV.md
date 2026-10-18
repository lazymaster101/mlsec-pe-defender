# dev/v4: development branch (built on top of `release/sure-shot-v3`)

Branch policy:
- `release/sure-shot-v3` is **frozen**. It holds the verified PASS submission; see
  `SURE_SHOT.md`.
- All new work lands here, on `dev/v4` or on branches cut from it.
- A change is promoted to a new `release/*` branch only after it passes the same gates as
  v3: grouped-CV gain, no robustness regression, ARM64 + x86-64 container verification,
  and a single post-freeze run on the course set.

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
