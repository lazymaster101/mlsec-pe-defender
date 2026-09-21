# MLSEC Defender — Windows PE malware classifier

A self-contained Docker image that serves a random-forest Windows PE malware
classifier over HTTP. The runtime has no scikit-learn, no pandas, no scipy, and
never unpickles anything: the forest ships as plain `.npy` arrays, memory-mapped
at startup.

> **Deployed model: `rf_adv` (retrained + adversarially hardened).** The image no
> longer ships the supplied `NFS_21_...MLSEC20.pkl`. It ships a RandomForest trained on
> a temporally-split EMBER 2018 corpus plus recent (2020–2026) MalwareBazaar malware
> **plus functionality-preserving adversarial variants of that malware**, served at a
> threshold calibrated to 1 % FPR (**0.820932**). The supplied model gave **13 % FPR**
> at its 0.25 threshold and detected only **9 % of recent malware** at a sane 1 %-FPR
> threshold, and it collapsed to **9 %** under a cheap functionality-preserving evasion.
> `rf_adv` fixes all three, measured on **held-out** malware: 1 % FPR by construction,
> **66 % recent-malware detection** (the same cheap evasion is now held at **55 %** vs
> the clean model's 7 %). This costs ~2.8 pt EMBER TPR (79.5 → 76.7 %) and ~7.6 pt clean
> held-out recent detection (66 → 59 %) versus the clean `rf_augmented`, and it does
> **not** harden an untrained attack mechanism or full feature-mimicry. See
> [`../dataset/docs/COMPARISON_REPORT.md`](../dataset/docs/COMPARISON_REPORT.md) §8/§10
> and [`../dataset/docs/PITFALL_AUDIT.md`](../dataset/docs/PITFALL_AUDIT.md) for the
> full methodology, CIs, and honest limits. The clean `rf_augmented` (threshold 0.7565)
> remains in the repo and is one `DF_MODEL_DIR` away for the clean-only comparison. The
> NFS feature-extraction and array-export pipeline below is unchanged and still
> validated bit-exactly against the supplied model.

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

* **FPR calibrated to 1 %** on 30 000 held-out EMBER benign; 0.5 % on the 200-PE recent
  goodware set; 0/7 on the classic goodware spot check.
* **EMBER temporal TPR @ 1 % FPR = 76.7 %** (`rf_augmented` 79.5 %, supplied 71.2 %).
  The **≥ 95 % TPR goal is not reachable** in the NFS feature space (§6 of the report).
* **Held-out recent-malware detection 66 %** (`rf_adv` 59 %; supplied ~9 %), and **55 %**
  under a cheap functionality-preserving evasion (clean model 7 %). Adversarial-training
  limits are stated honestly: no transfer to an untrained mechanism, ~99 % evaded under
  full feature-mimicry (report §10).

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
| `DF_MODEL_DIR`             | `/app/models/nfs`| directory of exported arrays                   |
| `DF_MALWARE_THRESHOLD`     | `0.25`           | malicious when `P(malware) > threshold`        |
| `DF_FEATURE_MODE`          | `training`       | `training` or `legacy` (see above)             |
| `DF_PORT` / `DF_HOST`      | `8080` / `0.0.0.0` | listen address                               |
| `DF_WORKERS`               | `2`              | concurrent inference slots                     |
| `DF_REQUEST_BUDGET_SECONDS`| `4.0`            | answer `1` rather than overrun the 5 s budget  |
| `DF_MAX_BODY_BYTES`        | `67108864`       | larger bodies are drained and answered `1`     |

`0.25` is the competition default: `NeedForSpeedModel.predict_threshold` decides
`P(benign) < 0.75`, which is the same rule.

## Failing toward detection

The rules score a timed-out sample as a successful evasion, so every failure path
returns a decision inside the budget rather than an error:

* unparseable or truncated input → `1`
* work exceeding `DF_REQUEST_BUDGET_SECONDS` → `1` (the worker is abandoned, and
  `DF_WORKERS` bounds how many can pile up)
* body over `DF_MAX_BODY_BYTES` → drained without buffering, then `1`

The trade-off is that a *benign* file that cannot be parsed becomes a false
positive. This matches the upstream reference, which also returns `1` on
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
5-second budget. Set `DF_MALWARE_THRESHOLD` to whatever it recommends.

## Layout

```
defender/features.py   PE attribute extraction (lief), both schemas
defender/hashing.py    HashingVectorizer transform, sklearn-exact
defender/model.py      one-hot + hashing + MaxAbsScaler + forest traversal
defender/server.py     stdlib HTTP endpoint
models/nfs/            exported arrays, schema.json, manifest.json with SHA-256s
tools/export_legacy_model.py  offline pickle → arrays conversion (not in the image)
tools/evaluate.py      FPR/TPR measurement and threshold selection
tests/                 26 tests incl. sklearn-derived golden vectors
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
