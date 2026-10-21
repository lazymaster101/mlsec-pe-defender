# MLSEC Defender — Windows PE malware classifier

A self-contained Docker image that serves a random-forest Windows PE malware
classifier over HTTP. The runtime has no scikit-learn, no pandas, no scipy, and
never unpickles anything: the forest ships as plain `.npy` arrays, memory-mapped
at startup.

> **v3.3 (2026-10-20, branch `release/sure-shot-v3.1`).** `Dockerfile.ensemble` serves the v3.3
> layered detector: Authenticode trust (including the 2000 and 2006 generations of the Microsoft
> Code Signing PCA), Authenticode tamper, an embedded hidden-PowerShell command-line tell, LIEF-
> unparseable input failing toward detection, and the log-odds fusion of `ember_gbdt`, `rf_adv` and
> `ember_ft_v33` (800 rounds on 1,665 recent malware, near-duplicate builds of course samples
> removed). Course set, scored once per candidate: **50/50 malware, 0/50 goodware** (v3: 48/50).
> Gates, costs (sealed-holdout FPR on unsigned third-party EXEs 9.25 % → 10.3 %) and limits:
> [`../dataset/docs/V33_STATUS.md`](../dataset/docs/V33_STATUS.md); history in `V31_STATUS.md` and
> `V32_STATUS.md` (with the review errata). The paragraph below describes the older single-model
> `Dockerfile` image and is kept for the NFS pipeline documentation.

> **Single-model image: `rf_adv` (retrained + augmented with synthetic feature-space
> perturbations).** The image no longer ships the supplied `NFS_21_...MLSEC20.pkl`. It
> ships a RandomForest trained on a temporally-split EMBER 2018 corpus plus recent
> (2020–2026) MalwareBazaar malware **plus synthetic feature-space perturbations of that
> malware** (attribute-dict edits; no PE produced), served at threshold **0.820932**. That
> threshold was chosen to give 1 % FPR on a 30 000-row *subsample of the EMBER test file*;
> at the fixed threshold the full 100 000 test benign give **1.051 %** (Wilson 95 %
> 0.99–1.12 %), so "1 %" is a calibration fit, not a bound (review 2026-09-21, finding 1).
> The supplied model gave **13 % FPR** at its 0.25 threshold and detected only **9 % of
> recent malware** at a sane 1 %-FPR threshold, and it collapsed to **9 %** under a cheap
> feature-space perturbation. `rf_adv`, measured on **held-out** malware: **59 %
> recent-malware detection** (254/433; the clean `rf_augmented` reaches 66 %), and the
> same perturbation held at **55 %** vs the clean model's 7 %. This costs ~2.8 pt EMBER TPR
> (79.5 → 76.7 %) and ~7.6 pt clean held-out recent detection (66 → 59 %) versus the clean
> `rf_augmented`; it does **not** harden an untrained mechanism or full feature-mimicry,
> and **no executable adversarial binary was produced or tested** (finding 3). See
> [`../dataset/docs/COMPARISON_REPORT.md`](../dataset/docs/COMPARISON_REPORT.md) §8/§10
> and [`../dataset/docs/PITFALL_AUDIT.md`](../dataset/docs/PITFALL_AUDIT.md) for the
> full methodology, CIs, and honest limits. The clean `rf_augmented` (threshold 0.756536)
> remains in the repo (`dataset/models/nfs_rf_augmented`) but **not in this image**, which
> copies only `rf_adv`: switching means rebuilding with its arrays and setting
> `DF_MALWARE_THRESHOLD=0.756536`. The NFS feature-extraction and array-export pipeline
> below is unchanged and still validated bit-exactly against the supplied model.

## Quick start

```bash
docker build -t mlsec-defender .
docker run --rm -m 1g -p 8080:8080 mlsec-defender
```

```bash
curl -XPOST --data-binary @sample.exe \
     -H "Content-Type: application/octet-stream" http://127.0.0.1:8080/
```

For an x86 grading host, build explicitly — results are bit-identical on both:

```bash
docker build --platform linux/amd64 -t mlsec-defender .
```

## API

| Method | Path      | Request                              | Response                     |
|--------|-----------|--------------------------------------|------------------------------|
| POST   | `/`       | `application/octet-stream`, PE bytes | `{"result": 0}` or `{"result": 1}` |
| GET    | `/model`  | —                                    | model metadata and live counters |
| GET    | `/health` | —                                    | `{"status": "ok"}`           |

`1` means malicious. A wrong `Content-Type` returns 400; everything else returns
200 with a decision, including bodies the parser rejects.

## Measured against the stated constraints

Apple M-series host, `docker run -m 1g`, 400 requests over real goodware and
header-mutated variants of it:

| Constraint             | Limit    | Measured                                      |
|------------------------|----------|-----------------------------------------------|
| Memory                 | ≤ 1 GB   | **76 MiB** steady state (7.4 % of the cap)     |
| Response time / sample | ≤ 5 s    | **mean 10 ms, p95 16 ms, p99 24 ms, max 40 ms** |
| Self-contained image   | —        | 380 MB model + 80 MB site-packages, no network |

Memory stays flat because the forest is memory-mapped: only the nodes an
actual traversal visits become resident, and those pages are file-backed and
reclaimable. An in-process worst case that touches the whole forest peaked at
246 MB. The amd64 image under emulation used 104 MiB.

> The table above was first measured on the clean `rf_augmented`. The now-deployed
> `rf_adv` (2.04 M nodes, 59 MB, 388 MB image) was verified in the running container
> (`docker run -m 1g`): **147 MiB** steady state (14 % of the cap), live-HTTP latency
> **mean 13 ms / p95 48 ms / max 66 ms**, 0/7 goodware false positives, 37/50 recent
> malware caught, and malformed input failing to `1`.

## Accuracy: what is and is not established

**Established — the runtime is numerically exact.** The sklearn-free runtime matches
an independent scikit-learn implementation to the bit, so the served probabilities are
exactly what the exported forest encodes (validated originally against the supplied
model's pickle, and the deployed `rf_adv` uses the same export/runtime path):

* The hashed-text block matches `HashingVectorizer` **exactly** on 133 documents
  including empty, unpadded, multi-space, non-ASCII and 300-token inputs, and
  `mmh3` matches sklearn's `murmurhash3_bytes_s32` on 200 000 random tokens.
* End-to-end probabilities match a reference built from sklearn's own
  `HashingVectorizer` / `OneHotEncoder` / `MaxAbsScaler` feeding a tree traversal:
  **max absolute difference 0.0** across 16 cases; the batch scorer used for evaluation
  matches the runtime to **5.6e-16** on 200 real samples.
* The Linux container and the amd64 container both reproduce those probabilities
  with **max absolute difference 0.0**.

**Established — FPR and TPR (for `rf_adv`).** Measured on labelled corpora, not asserted
(full numbers, CIs and method in [`../dataset/docs/COMPARISON_REPORT.md`](../dataset/docs/COMPARISON_REPORT.md)):

* **FPR 1.00 % on the 30 000-row calibration subsample** of the EMBER test file (the
  threshold was chosen there), **1.051 % on all 100 000 EMBER test benign** (1,051;
  Wilson 95 % 0.99–1.12 %), **1/60 on the held-out recent goodware** (1.7 %, Wilson
  0.3–8.9 %; 0/140 on the recent goodware it was trained on, which must not be pooled
  in); 0/7 on the classic goodware spot check.
* **EMBER temporal TPR @ 1 % FPR = 76.7 %** (`rf_augmented` 79.5 %, supplied 71.2 %).
  The **≥ 95 % TPR goal is not reachable** in the NFS feature space (§6 of the report).
* **Held-out recent-malware detection 59 %** for `rf_adv` (254/433; the clean
  `rf_augmented` 66 %; supplied ~9 %; 53 % on the 349 rows without a feature-identical
  training twin), and **55 %** under a cheap synthetic feature-space perturbation (clean
  model 7 %). Limits: no transfer to an untrained mechanism, ~99 % evaded under full
  feature-mimicry, and these are feature-space numbers — no adversarial binary was
  produced or executed (report §10).

Re-run any of this with `tools/evaluate.py` (this image) or the dataset tools
(`dataset/tools/evaluate_adversarial.py`) — see *Calibration* below.

## The feature-schema decision

This is the single highest-impact choice in the build, so it is called out
explicitly. The upstream MLSEC code extracts features **two different ways**:

* `train_classifier.py` (`JSONAttributeExtractor`) — what the model was trained on.
  It stores imported *function* names under the key `libraries` and *library* names
  under `functions`, and pads both with surrounding spaces.
* `defender/models/attribute_extractor.py` (`PEAttributeExtractor`) — what the
  reference server deploys. It does not swap the fields and does not pad.

The learned token pattern is `(?<=\s)(.*?)(?=\s)`, which requires whitespace on
*both* sides of a token. Padding is therefore not cosmetic: `"A B"` tokenises to
`[]`, while `" A B "` tokenises to `["a", "b"]`.

Scoring the same seven goodware samples both ways:

| Extractor schema             | Score range | Decisions at 0.25 |
|------------------------------|-------------|-------------------|
| `training` (trainer's schema) | 0.00 – 0.07 | **0/7 flagged**   |
| `legacy` (shipped deployment) | 0.39 – 0.75 | **7/7 flagged**   |

The shipped deployment extractor would have produced a 100 % false-positive rate on
ordinary goodware. This image therefore defaults to `DF_FEATURE_MODE=training`.
`legacy` remains selectable for comparison, but is not a sane operating point.

## Configuration

| Variable                   | Default          | Meaning                                        |
|----------------------------|------------------|------------------------------------------------|
| Variable | Image (`Dockerfile`) | Code default | Meaning |
|---|---|---|---|
| `DF_MODEL_DIR`             | `/app/models/rf_adv` | `models/nfs` | directory of exported arrays (manifest digests verified at load) |
| `DF_MALWARE_THRESHOLD`     | `0.820932` | `0.25` | malicious when `P(malware) > threshold` |
| `DF_FEATURE_MODE`          | `training` | `training` | `training` or `legacy` (see above) |
| `DF_PORT` / `DF_HOST`      | `8080` / `0.0.0.0` | same | listen address |
| `DF_WORKERS`               | `2` | `2` | inference worker processes; also the admission bound |
| `DF_WORKER_MODE`           | `process` | `process` | `process` = forked, killable workers; `thread` = legacy pool that cannot interrupt native calls (logged as a warning; never used in the images) |
| `DF_REQUEST_BUDGET_SECONDS`| `4.5` | `4.0` | total budget from headers-in to answer: body read + wait for a worker + inference; anything that cannot finish is answered `1` |
| `DF_MAX_BODY_BYTES`        | `67108864` | same | larger bodies are drained and answered `1` |

`0.25` is the competition default (`NeedForSpeedModel.predict_threshold` decides
`P(benign) < 0.75`, the same rule) and is what the supplied-model tests assert; the image
serves `rf_adv` at `0.820932`.

## Failing toward detection

The rules score a timed-out sample as a successful evasion, so every failure path
returns a decision inside the budget rather than an error:

* unparseable input (LIEF rejects it) → `1`
* a body that stalls or is truncated before the deadline → `1` (the socket carries a
  read deadline; the connection is then closed)
* no inference worker free before the request's own deadline → `1` (`saturated`;
  admission is bounded by `DF_WORKERS`, nothing is queued past its deadline, and no
  input buffer outlives its request)
* inference exceeding the remaining budget → `1` (`overrun`): the worker **process is
  SIGKILLed** and replaced, so a native call holding the interpreter lock cannot push
  the answer past the budget; a worker that crashes is likewise replaced (`worker_failed`)
* body over `DF_MAX_BODY_BYTES` → drained without buffering, then `1`

`DF_REQUEST_BUDGET_SECONDS` is counted from the moment the request headers are in and
covers body read, worker wait and inference; the request body is streamed from the
client socket into the worker, so this process never holds a whole sample. What the
server cannot control is time spent before the headers arrive. All of this replaced the
earlier thread pool, whose timeouts abandoned the caller but not the work (review
2026-09-21, finding 2; `tests/test_workers.py`, `tests/test_server_deadlines.py`).

The trade-off is that a *benign* file that cannot be parsed, or whose upload stalls,
becomes a false positive. This matches the upstream reference, which also returns `1` on
`lief.bad_format`.

## Calibration

```bash
# in-process: yields probabilities, so it can sweep thresholds
python tools/evaluate.py --benign path/to/goodware --malicious path/to/malware \
                         --target-fpr 0.01 --min-tpr 0.95 --json report.json

# end-to-end through a running container
python tools/evaluate.py --benign ... --malicious ... --url http://127.0.0.1:8080
```

It reports FPR/TPR at the deployed threshold, the score distribution per class,
the best threshold meeting the FPR target, and latency percentiles against the
5-second budget. Set `DF_MALWARE_THRESHOLD` to whatever it recommends — on a calibration
set that is disjoint from the one you then report on. In `--url` runs every sample has a
`--deadline` (default 5.0 s, the challenge's): an answer that is late, missing or
malformed counts against the detector (malware = miss, goodware = false positive), stays
in the denominator, and is listed under operational errors (review 2026-09-21, finding 4).

## Layout

```
defender/features.py   PE attribute extraction (lief), both schemas
defender/hashing.py    HashingVectorizer transform, sklearn-exact
defender/model.py      one-hot + hashing + MaxAbsScaler + forest traversal
defender/server.py     stdlib HTTP endpoint: read deadline, bounded admission, fail toward detection
defender/workers.py    forked inference workers, SIGKILLed at the deadline and replaced
models/nfs/            exported arrays, schema.json, manifest.json with SHA-256s (verified at load)
tools/export_legacy_model.py  offline pickle → arrays conversion (not in the image)
tools/evaluate.py      FPR/TPR measurement and threshold selection (5 s deadline over HTTP)
tests/                 9x tests incl. sklearn-derived golden vectors, deadline and integrity tests
```

## Tests

```bash
python -m unittest discover -s tests -t .
```

Golden fixtures were generated *by* scikit-learn, so the suite pins sklearn
equivalence without requiring sklearn at runtime.

## Model conversion

`tools/export_legacy_model.py` converts the supplied pickle into the shipped
arrays. It runs offline and is deliberately not part of the image. The pickle is
read only after a static `pickletools` opcode audit and through an allowlisting
unpickler that maps every sklearn class to an inert state holder, so no estimator
constructor or `__setstate__` from the pickle ever executes. The source SHA-256 is
pinned. Do not point this tool at untrusted pickles.

```bash
python tools/export_legacy_model.py NFS_21_ALL_hash_50000_WITH_MLSEC20.pkl models/nfs
```
